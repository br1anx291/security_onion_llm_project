import logging
import subprocess
import time
import urllib3

import pandas as pd
import time
from datetime import datetime, date, timedelta
from elasticsearch import Elasticsearch
from elasticsearch_dsl import Search


# Local application/library specific imports
from config import (
    SSH_TUNNEL_LOCAL_PORT,
    SSH_TUNNEL_REMOTE_PORT,
    REMOTE_USERNAME,
    REMOTE_HOST,
    ELASTIC_HOST,
    ELASTIC_USER,
    ELASTIC_PASS,
    ALERT_SEVERITY,
)

# Setup logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")


# Establish an SSH tunnel to Security Onion for Elasticsearch access
def start_ssh_tunnel():
    try:
        local_port = SSH_TUNNEL_LOCAL_PORT
        remote_port = SSH_TUNNEL_REMOTE_PORT 
        ssh_target = f"{REMOTE_USERNAME}@{REMOTE_HOST}"

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
            [ELASTIC_HOST],
            ca_certs=False, verify_certs=False,
            basic_auth=(ELASTIC_USER, ELASTIC_PASS)
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
def retrieve_alerts_by_day(es, severity, target_date: date):
    """
    Query Suricata alerts from Elasticsearch for a specific day.

    :param es: Elasticsearch connection object.
    :param severity: List of severity levels to filter by.
    :param target_date: The specific date (datetime.date object) to retrieve alerts for.
    :return: A pandas DataFrame with the alerts, or None if an error occurs.
    """
    try:
        # Xác định khoảng thời gian cho ngày mục tiêu (từ 00:00:00 đến < 00:00:00 ngày hôm sau)
        start_of_day = datetime.combine(target_date, datetime.min.time())
        end_of_day = start_of_day + timedelta(days=1)

        # Định dạng thời gian theo chuẩn ISO 8601 mà Elasticsearch sử dụng (UTC)
        gte_timestamp = start_of_day.isoformat() + 'Z'
        lt_timestamp = end_of_day.isoformat() + 'Z'
        
        logging.info(f"Retrieving alerts for {target_date.strftime('%Y-%m-%d')}...")

        search_context = Search(using=es, index='*logs-*',doc_type='doc') \
            .query("query_string", query="event.module:suricata") \
            .filter("terms", **{"rule.severity": severity}) \
            .filter('range', **{
                '@timestamp': {
                    'gte': gte_timestamp,  # Greater than or equal to
                    'lt': lt_timestamp      # Less than
                }
            })

        response = search_context.execute()

        if not response.success():
            logging.warning(f"Failed to retrieve alerts for {target_date}.")
            return None
        else:

            raw_alerts_list = [d.to_dict() for d in search_context.scan()]
            logging.info(f"Retrieved {len(raw_alerts_list)} alerts for {target_date.strftime('%Y-%m-%d')}.")
            return raw_alerts_list
            
    except Exception as e:
        logging.error(f"Error retrieving alerts for {target_date}: {e}")
        return None
    
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
        
def export_to_pickle(df, path):
    try:

        with open(path, 'wb') as f:
            pickle.dump(df, f)
        logging.info(f"DataFrame object successfully saved to {path}")
    except Exception as e:
        logging.error(f"Error saving pickle file: {e}")

        
if __name__ == "__main__":
    start_ssh_tunnel()
    es = connect_elasticsearch()

    if es:
        today = date(2025, 7, 2)
        alerts_df = retrieve_alerts_by_day(es, ALERT_SEVERITY, today)
        if alerts_df:
            logging.info(f"Đã lấy về {len(alerts_df)} cảnh báo. Hiển thị dữ liệu thô phức tạp:")
            print("==========================================================")
            # Dùng print() để xem dạng chuỗi ký tự gốc, không định dạng
            print(alerts_df)
            print("==========================================================")
        else:
            logging.warning("Không tìm thấy cảnh báo nào từ Elasticsearch.")
        
    
    else:
        logging.error("Cannot proceed without Elasticsearch connection.")


