from config import *
from elasticsearch import Elasticsearch
from elasticsearch_dsl import Search
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import timedelta
import urllib3
import subprocess
import time
import logging
import pandas as pd
import numpy as np
# Setup logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")


# Establish an SSH tunnel to Security Onion for Elasticsearch access
def start_ssh_tunnel():
    try:
        local_port = ssh_tunnel_local_port
        remote_port = ssh_tunnel_remote_port
        ssh_target = f"{remote_username}@{remote_host}"

        logging.info(f"Starting SSH tunnel: localhost:{local_port} -> {ssh_target}:{remote_port}")

        subprocess.Popen([
            'ssh', '-N',
            '-L', f'{local_port}:localhost:{remote_port}',
            ssh_target
        ])

        time.sleep(5)  # Wait for tunnel to stabilize
        logging.info("SSH tunnel established successfully.")
    except Exception as e:
        logging.error(f"Error starting SSH tunnel: {e}")


# Create connection to Elasticsearch and validate connectivity
def connect_elasticsearch():
    try:
        es = Elasticsearch(
            [elastic_host],
            ca_certs=False, verify_certs=False,
            basic_auth=(elastic_user, elastic_pass)
        )
        if es.ping():
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            logging.info("Connected to Elasticsearch.")
            return es
        else:
            logging.warning("Elasticsearch ping failed.")
            return None
    except Exception as e:
        logging.error(f"Elasticsearch connection error: {e}")
        return None


# Query Suricata alerts from Elasticsearch based on severity level
def retrieve_alerts(es, severity):
    try:
        search_context = Search(using=es, index='*logs-*', doc_type='doc') \
            .query("query_string", query="event.module:suricata") \
            .filter("terms", **{"rule.severity": severity})

        response = search_context.execute()

        if not response.success():
            logging.warning("Failed to retrieve alerts.")
            return None
        else:
            alerts_df = pd.DataFrame((d.to_dict() for d in search_context.scan()))
            logging.info(f"Retrieved {len(alerts_df)} alerts.")
            return alerts_df
    except Exception as e:
        logging.error(f"Error retrieving alerts: {e}")
        return None


# Flatten nested dictionaries inside alert fields for better data manipulation
def normalize_alerts(alerts_df):
    if alerts_df is None or alerts_df.empty:
        print("⚠️ No alerts to normalize.")
        return alerts_df

    dict_cols = [col for col in alerts_df.columns if isinstance(alerts_df[col].iloc[0], dict)]

    for col in dict_cols:
        try:
            flattened = pd.json_normalize(alerts_df[col])
            flattened.columns = [f"{col}.{subcol}" for subcol in flattened.columns]
            alerts_df = alerts_df.drop(columns=[col]).join(flattened)
        except Exception as e:
            print(f"⚠️ Could not normalize column '{col}': {e}")

    return alerts_df


# Select important fields from alert logs for further enrichment and analysis
def select_columns(alerts_df):
    """
    Lọc ra các trường quan trọng từ log Suricata để enrich và phân tích.
    """
    columns = [
        # Timestamp and identifiers
        "@timestamp", "log.id.uid", "message",

        # Network information
        "source.ip", "source.port", "destination.ip", "destination.port",
        "network.transport", "network.community_id",

        # Suricata rule information
        "rule.name", "rule.category",
        "rule.signature", "rule.signature_id",


        # Rule metadata (MITRE, malware, severity)
        "rule.metadata.mitre_tactic_id", "rule.metadata.mitre_technique_id",
        "rule.metadata.mitre_tactic_name", "rule.metadata.mitre_technique_name",
        "rule.metadata.signature_severity", "rule.metadata.malware_family",

        # Event metadata
        "event.severity", "event.module", "event.dataset", "event.category",
    ]

    if alerts_df is not None:
        existing_columns = [col for col in columns if col in alerts_df.columns]
        missing_columns = set(columns) - set(existing_columns)
        if missing_columns:
            print(f"⚠️ Missing columns (not in alert data): {missing_columns}")
        return alerts_df[existing_columns]
    else:
        print("⚠️ alerts_df is None — No data available.")
        return None


# Export filtered and structured alert data to a CSV file
def export_to_csv(df, path):
    try:
        df.to_csv(path, index=False)
        logging.info(f"Flow info exported to {path}")
    except Exception as e:
        logging.error(f"Error saving CSV: {e}")


# Export filtered and structured alert data to a .log file
def export_to_log(df, path):
    try:
        with open(path, 'w', encoding='utf-8') as log_file:
            log_file.write(df.to_string(index=False))
        logging.info(f"Flow info exported to log file: {path}")
    except Exception as e:
        logging.error(f"Error saving log file: {e}")
        


# Export filtered and structured alert data to a .json file
def export_to_json(df, path):
    try:
        df.to_json(path, orient='records', indent=4, force_ascii=False)
        logging.info(f"Flow info exported to JSON file: {path}")
    except Exception as e:
        logging.error(f"Error saving JSON file: {e}")
        
if __name__ == "__main__":
    start_ssh_tunnel()
    es = connect_elasticsearch()

    if es:
        alerts_df = retrieve_alerts(es, alert_severity)

        if alerts_df is None or alerts_df.empty:
            logging.warning("No alerts retrieved from Elasticsearch. Exiting.")
        else:
                export_to_json(alerts_df, alert_output_path)
    else:
        logging.error("Cannot proceed without Elasticsearch connection.")
