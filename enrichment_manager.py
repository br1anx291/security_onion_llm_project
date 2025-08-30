# security_onion_llm_project/enrichment_manager.py

import subprocess
import json
import logging
import os
from datetime import datetime
from typing import Dict, Any, Tuple, List
from concurrent.futures import ThreadPoolExecutor, as_completed

# Local application imports
from config import ZEEK_LOGS_DIR, CONN_LOG_TIME_WINDOW_SECONDS, MAX_WORKERS
from log_helper import find_log_files
from collectors.conn_collector import ConnCollector
from collectors.dns_collector import DnsCollector
from collectors.http_collector import HttpCollector
from collectors.files_collector import FilesCollector
from collectors.ssl_collector import SslCollector

# --- Global Configuration ---
LOG_FORMAT = "%(asctime)s [%(threadName)-12.12s] [%(levelname)-5.5s]  %(message)s"
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)


class EnrichmentManager:
    """
    Manages the process of enriching Suricata alerts with contextual data from Zeek logs.
    It fetches related logs, processes them through various collectors, classifies
    the evidence based on severity, and builds a structured JSON output.
    """

    # --- Signal Classification Rules ---
    # Defines the rules for classifying evidence into different severity levels.
    # Each rule specifies the collector, the data path to check, the type of check,
    # and the value to match against.
    SIGNAL_CLASSIFICATION = {
        "CRITICAL": [
            # HTTP: Anomalous or malformed user agents often indicate malicious tools.
            {"collector": "http", "path": "analysis.user_agent_category", "check": "equals", "value": "Anomalous/Malformed"},
            {"collector": "http", "path": "analysis.file_transfer_risk", "check": "startswith", "value": "Suspicious Upload"},
            
            # DNS: Combines the highest risk behaviors: DGA and Beaconing.
            {"collector": "dns", "path": "analysis.overall_assessment", "check": "startswith", "value": "Potential Threat"},
            
            # FILES: The overall session is deemed critical, often due to multiple high-risk indicators.
            {"collector": "files", "path": "analysis.highest_threat_level", "check": "equals", "value": "Critical"},
            # A single file has an extremely high risk score, catching severe individual threats.
            {"collector": "files", "path": "evidence.findings[*].risk_score", "check": "gte", "value": 90},
            
            # SSL: High confidence that the SSL/TLS session is associated with a known threat.
            {"collector": "ssl", "path": "analysis.overall_assessment", "check": "startswith", "value": "High Confidence Threat"},
        ],
        "HIGH": [
            # CONN: Connection history indicates clear scanning or attack patterns.
            {"collector": "conn", "path": "analysis.history_analysis.severity", "check": "equals", "value": "High"},
            
            # HTTP: Executable content downloaded, a common malware delivery method.
            {"collector": "http", "path": "analysis.download_risk", "check": "equals", "value": "Executable Content Detected"},
            # Direct-to-IP connections can bypass domain-based security controls.
            {"collector": "http", "path": "analysis.destination_analysis", "check": "equals", "value": "Direct-to-IP Connection"},
            # User agents associated with command-line tools or scripts (e.g., curl, PowerShell).
            {"collector": "http", "path": "analysis.user_agent_category", "check": "equals", "value": "Scripting/Tool"},
            {"collector": "http", "path": "analysis.content_risk", "check": "equals", "value": "Suspicious Content Detected"},
            {"collector": "http", "path": "analysis.file_transfer_risk", "check": "startswith", "value": "Suspicious Download"},
            
            # SSL: The SSL/TLS session has suspicious characteristics but lacks definitive proof of malice.
            {"collector": "ssl", "path": "analysis.overall_assessment", "check": "startswith", "value": "Suspicious Anomaly"},
            
            # DNS: Query patterns indicative of Domain Generation Algorithms (DGA).
            {"collector": "dns", "path": "analysis.observed_query_pattern", "check": "equals", "value": "High Entropy (DGA-like)"},
            # Repetitive queries indicative of C2 beaconing.
            {"collector": "dns", "path": "analysis.observed_query_pattern", "check": "equals", "value": "Repetitive (Beaconing-like)"},
            
            # FILES: Evasion techniques were detected (e.g., hiding data, obfuscation).
            {"collector": "files", "path": "analysis.evasion_techniques_detected", "check": "equals", "value": "Yes"},
            # File type camouflage (e.g., an executable disguised as a JPG).
            {"collector": "files", "path": "evidence.findings[*].reasons", "check": "contains", "value": "MIME_MISMATCH"},
            # High entropy suggests encrypted or packed malware.
            {"collector": "files", "path": "evidence.findings[*].reasons", "check": "contains", "value": "HIGH_ENTROPY"},
        ],
        "MEDIUM": [
            # CONN: History suggests probing or other suspicious, but not overtly aggressive, behavior.
            {"collector": "conn", "path": "analysis.history_analysis.severity", "check": "equals", "value": "Medium"},
            
            # HTTP: Outdated browsers are often unpatched and vulnerable.
            {"collector": "http", "path": "analysis.user_agent_category", "check": "equals", "value": "Outdated Browser"},
            # A high ratio of client errors (4xx) can indicate scanning or forced browsing.
            {"collector": "http", "path": "statistics.client_error_ratio", "check": "gte", "value": 0.7},
            {"collector": "http", "path": "analysis.transfer_volume", "check": "equals", "value": "Large"},

            # DNS: Queries for domains with TLDs commonly used for malicious purposes (.xyz, .cc, etc.).
            {"collector": "dns", "path": "analysis.observed_tld_risk", "check": "equals", "value": "Contains Monitored TLDs"},
            
            # FILES: At least one suspicious file was detected in the session.
            {"collector": "files", "path": "statistics.suspicious_files_count", "check": "gte", "value": 1},
            # File extension is commonly associated with malware (.exe, .dll, .bat).
            {"collector": "files", "path": "evidence.findings[*].reasons", "check": "contains", "value": "SUSPICIOUS_EXTENSION"},
            # MIME type is commonly associated with malware.
            {"collector": "files", "path": "evidence.findings[*].reasons", "check": "contains", "value": "SUSPICIOUS_MIME"},

            # SSL: Informational findings that are not directly suspicious but add context.
            {"collector": "ssl", "path": "analysis.overall_assessment", "check": "startswith", "value": "Informational"},
        ],
        "LOW": [
            # DNS: Low TTL values can be used in fast-flux DNS to hide C2 infrastructure.
            {"collector": "dns", "path": "analysis.observed_ttl_behavior", "check": "startswith", "value": "Low"},
            
            # SSL: Handshake failures can indicate network errors, misconfigurations, or MITM attempts.
            {"collector": "ssl", "path": "analysis.handshake_status", "check": "equals", "value": "Failed"},
        ]
    }

    def __init__(self):
        """Initializes the EnrichmentManager and its collectors."""
        self.all_collectors = [
            HttpCollector(ZEEK_LOGS_DIR), DnsCollector(ZEEK_LOGS_DIR),
            FilesCollector(ZEEK_LOGS_DIR), SslCollector(ZEEK_LOGS_DIR),
            ConnCollector(ZEEK_LOGS_DIR)
        ]
        self.collectors_map = {c.collector_name: c for c in self.all_collectors}

    def enrich_and_prompt(self, suricata_alert: dict) -> Dict[str, Any]:
        """
        Main entry point to enrich a Suricata alert.

        Args:
            suricata_alert: The raw alert dictionary from Elasticsearch.

        Returns:
            A dictionary containing the structured, enriched alert information.
        """
        uid, log_cache = self._find_and_fetch_all_logs(suricata_alert)

        if not uid or not log_cache:
            # If no related logs are found, return the basic alert info.
            return self._build_json_output(suricata_alert, None, {}, {}, {}, {}, {})

        # Process connection logs first to establish a baseline context.
        conn_collector = self.collectors_map['conn']
        conn_evidence = conn_collector.collect(log_cache.get('conn', []))

        # Process all other log types.
        all_other_evidence = {}
        other_collectors = [c for c in self.all_collectors if c.collector_name != 'conn']

        for collector in other_collectors:
            result = collector.collect(log_cache.get(collector.collector_name, []))
            if result:
                all_other_evidence[collector.collector_name] = result

        # Classify the collected evidence based on predefined rules.
        classified_evidence = self._classify_evidence(all_other_evidence)

        # Build the final JSON output.
        return self._build_json_output(suricata_alert, conn_evidence, *classified_evidence)

    # --- Private Helper Methods ---

    def _find_and_fetch_all_logs(self, suricata_alert: dict) -> Tuple[str | None, Dict[str, List[str]]]:
        """
        Finds and fetches all Zeek logs related to a Suricata alert.

        The search strategy is:
        1. Try to find conn logs using the alert's community_id, first in historical logs,
           then falling back to the 'current' log directory.
        2. If community_id fails, fall back to a 5-tuple search in historical logs.
        3. Once a matching conn log (and its UID) is found, use the UID to grep
           for all related logs (http, dns, ssl, files).

        Args:
            suricata_alert: The alert dictionary.

        Returns:
            A tuple containing the UID and a dictionary of raw log lines, or (None, {}) if not found.
        """
        timestamp = self._extract_timestamp_from_alert(suricata_alert)
        if timestamp is None:
            logging.warning("Exiting: Could not extract timestamp from alert.")
            return None, {}

        # First, determine the set of historical conn.log files to search.
        historical_conn_files = find_log_files(ZEEK_LOGS_DIR, "conn", timestamp)
        if not historical_conn_files:
            logging.warning(f"No historical conn.log files found for timestamp {timestamp}. Will check 'current' directory if needed.")

        all_raw_conn_lines = []
        community_id = suricata_alert.get("network", {}).get("community_id")

        # Strategy 1: Search by community_id
        if community_id:
            logging.info(f"Searching for community_id '{community_id}' in historical files: {historical_conn_files}")
            for log_file in historical_conn_files:
                result = subprocess.run(['rg', '-z', f'"community_id":"{community_id}"', log_file], capture_output=True, text=True, check=False)
                if result.returncode <= 1 and result.stdout:
                    lines = [line for line in result.stdout.replace('\0', '\n').strip().split('\n') if line]
                    all_raw_conn_lines.extend(lines)

            # Fallback to 'current' directory if nothing found in historical logs
            if not all_raw_conn_lines:
                logging.info(f"Community_id not found in historical logs. Falling back to 'current' directory.")
                current_log_dir = os.path.join(ZEEK_LOGS_DIR, "current")
                if os.path.isdir(current_log_dir):
                    for filename in os.listdir(current_log_dir):
                        if filename.startswith("conn.") and filename.endswith(".log"):
                            current_log_file = os.path.join(current_log_dir, filename)
                            result = subprocess.run(['rg', '-z', f'"community_id":"{community_id}"', current_log_file], capture_output=True, text=True, check=False)
                            if result.returncode <= 1 and result.stdout:
                                lines = [line for line in result.stdout.replace('\0', '\n').strip().split('\n') if line]
                                all_raw_conn_lines.extend(lines)

        # Strategy 2: Fallback to 5-tuple search if community_id search failed
        if not all_raw_conn_lines:
            logging.info("Community_id search failed. Falling back to 5-tuple search in historical logs.")
            try:
                src_ip, src_port = suricata_alert['source']['ip'], suricata_alert['source']['port']
                dest_ip, dest_port = suricata_alert['destination']['ip'], suricata_alert['destination']['port']
                proto = suricata_alert.get('network', {}).get('transport', '').lower()
                if not proto:
                    proto = json.loads(suricata_alert['message']).get('proto', '').lower()

                for log_file in historical_conn_files:
                    p1 = subprocess.Popen(['rg', f'"id.orig_h":"{src_ip}"', log_file], stdout=subprocess.PIPE, text=True)
                    p2 = subprocess.Popen(['rg', f'"id.orig_p":{src_port}'], stdin=p1.stdout, stdout=subprocess.PIPE, text=True)
                    p3 = subprocess.Popen(['rg', f'"id.resp_h":"{dest_ip}"'], stdin=p2.stdout, stdout=subprocess.PIPE, text=True)
                    p4 = subprocess.Popen(['rg', f'"id.resp_p":{dest_port}'], stdin=p3.stdout, stdout=subprocess.PIPE, text=True)
                    p5 = subprocess.Popen(['rg', f'"proto":"{proto}"'], stdin=p4.stdout, stdout=subprocess.PIPE, text=True)
                    p1.stdout.close(); p2.stdout.close(); p3.stdout.close(); p4.stdout.close()
                    result_stdout, _ = p5.communicate()
                    if result_stdout:
                        all_raw_conn_lines.extend(result_stdout.strip().split('\n'))
            except (KeyError, TypeError, json.JSONDecodeError):
                return None, {}

        # Filter candidates by time window and find the best match
        time_relevant_candidates = []
        for line in all_raw_conn_lines:
            if not line.strip(): continue
            try:
                log_entry = json.loads(line)
                ts = float(log_entry.get('ts', 0))
                if abs(ts - timestamp) < CONN_LOG_TIME_WINDOW_SECONDS:
                    time_relevant_candidates.append(log_entry)
            except (json.JSONDecodeError, ValueError, TypeError) as e:
                logging.warning(f"Skipping malformed conn log line. Error: {e}. Line: '{line[:100]}...'")

        if not time_relevant_candidates:
            logging.warning("No time-relevant conn log entries found after searching.")
            return None, {}

        # The "best" match is assumed to be the one with the longest duration.
        best_match = max(time_relevant_candidates, key=lambda x: float(x.get('duration', -1) or -1), default=None)
        if not best_match or 'uid' not in best_match:
            return None, {}

        uid = best_match.get('uid')
        log_cache = {'conn': [json.dumps(c) for c in time_relevant_candidates if c.get('uid') == uid]}

        # Use the found UID to fetch all other related logs in parallel.
        def _grep_worker(log_type: str) -> Tuple[str, List[str]]:
            # Always search historical logs for context consistency.
            log_files = find_log_files(ZEEK_LOGS_DIR, log_type, timestamp)
            if not log_files: return log_type, []
            matching_lines = []
            for log_file in log_files:
                result = subprocess.run(['rg', uid, log_file], capture_output=True, text=True, check=False)
                if result.returncode <= 1 and result.stdout:
                    matching_lines.extend(result.stdout.strip().split('\n'))
            return log_type, matching_lines

        log_types_to_fetch = ['http', 'dns', 'ssl', 'files']
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            future_to_log_type = {executor.submit(_grep_worker, log_type): log_type for log_type in log_types_to_fetch}
            for future in as_completed(future_to_log_type):
                log_type, result_lines = future.result()
                log_cache[log_type] = result_lines

        return uid, log_cache

    def _classify_evidence(self, all_evidence: Dict[str, Any]) -> Tuple[Dict, Dict, Dict, Dict, Dict]:
        """
        Classifies collected evidence based on the SIGNAL_CLASSIFICATION rules.

        It iterates from CRITICAL to LOW severity. Once a collector's evidence is
        classified, it is not considered for lower severity levels. Evidence that
        does not match any rule is placed in the 'reference' category.

        Args:
            all_evidence: A dictionary of evidence from all collectors.

        Returns:
            A tuple of dictionaries for each severity level and reference evidence.
        """
        severity_levels = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        classified_evidence = {level: {} for level in severity_levels}
        reference_evidence = {}
        classified_collectors = set()

        for severity in severity_levels:
            rules = self.SIGNAL_CLASSIFICATION.get(severity, [])
            for rule in rules:
                collector_name = rule["collector"]

                # If this collector's data has already been classified at a higher severity, skip.
                if collector_name in classified_collectors:
                    continue

                data = all_evidence.get(collector_name)
                if not data:
                    continue

                path = rule["path"]
                check_type = rule["check"]
                expected_value = rule["value"]
                
                actual_value = self._get_nested_value(data, path)
                match_found = False

                # Handle different check types
                if actual_value is None:
                    continue

                if check_type == "equals" and actual_value == expected_value:
                    match_found = True
                elif check_type == "startswith" and isinstance(actual_value, str) and actual_value.startswith(expected_value):
                    match_found = True
                elif check_type == "gte" and isinstance(actual_value, (int, float)) and actual_value >= expected_value:
                    match_found = True
                elif check_type == "contains" and isinstance(actual_value, list) and expected_value in actual_value:
                    match_found = True
                
                if match_found:
                    classified_evidence[severity][collector_name] = data
                    classified_collectors.add(collector_name)
                    # Break from the inner loop once a collector is classified to avoid multiple classifications
                    break 

        # Add any unclassified evidence to the reference category for context.
        for collector_name, data in all_evidence.items():
            if data and collector_name not in classified_collectors:
                reference_evidence[collector_name] = data

        return (
            classified_evidence["CRITICAL"],
            classified_evidence["HIGH"],
            classified_evidence["MEDIUM"],
            classified_evidence["LOW"],
            reference_evidence
        )
        
    def _build_json_output(self, alert: dict, conn_data: dict | None,
                          critical_evidence: dict, high_evidence: dict,
                          medium_evidence: dict, low_evidence: dict,
                          reference_evidence: dict) -> Dict[str, Any]:
        """Constructs the final JSON object to be returned."""
        rule_info = alert.get('rule', {})
        alert_output = {
            "signature": rule_info.get('name', 'N/A'),
            "category": rule_info.get('category', 'N/A'),
            "timestamp": alert.get('@timestamp', 'N/A')
        }

        final_output = {"alert": alert_output}

        # Add connection details if available
        if conn_data:
            conn_output = {}
            if conn_data.get('identity'):
                conn_output['identity'] = conn_data['identity']
            if conn_data.get('statistics'):
                conn_output['statistics'] = conn_data['statistics']
            if conn_data.get('analysis'):
                conn_output['analysis'] = conn_data['analysis']
            if conn_output:
                final_output["connection"] = conn_output

        # Dynamically build the evidence block, only including severities with findings.
        evidence_output = {}
        if critical_evidence:
            evidence_output["critical"] = critical_evidence
        if high_evidence:
            evidence_output["high"] = high_evidence
        if medium_evidence:
            evidence_output["medium"] = medium_evidence
        if low_evidence:
            evidence_output["low"] = low_evidence
        if reference_evidence:
            evidence_output["reference"] = reference_evidence
            
        if evidence_output:
            final_output["evidence"] = evidence_output

        return final_output

    def _extract_timestamp_from_alert(self, alert: dict) -> float | None:
        """Extracts and normalizes the timestamp from the alert message."""
        try:
            message_data = json.loads(alert['message'])
            ts_str_raw = message_data['timestamp']
            # Normalize different timezone formats to be compatible with fromisoformat
            ts_str_normalized = ts_str_raw.replace('Z', '+00:00').replace('+0000', '+00:00')
            return datetime.fromisoformat(ts_str_normalized).timestamp()
        except (KeyError, TypeError, json.JSONDecodeError, ValueError):
            return None

    def _get_nested_value(self, data: Dict[str, Any], path: str) -> Any:
        """
        Retrieves a value from a nested dictionary using a dot-separated path.
        Handles list wildcards '[*]' to check values within a list of objects.
        
        Example paths:
        - 'a.b.c' -> data['a']['b']['c']
        - 'a.b[*].c' -> will return a list [item['c'] for item in data['a']['b']]
        """
        keys = path.split('.')
        current_value = data
        for key in keys:
            if '[*]' in key:
                # Handle list wildcard case
                list_key, rest_of_key = key.split('[*]')
                if rest_of_key.startswith('.'):
                    rest_of_key = rest_of_key[1:]
                
                target_list = current_value.get(list_key)
                if not isinstance(target_list, list):
                    return None # Path is invalid if the target is not a list
                
                # If there's a key after the wildcard, extract that key from each item in the list
                if rest_of_key:
                    return [self._get_nested_value(item, rest_of_key) for item in target_list if isinstance(item, dict)]
                else: # If wildcard is the last part, return the whole list
                    return target_list

            elif isinstance(current_value, dict) and key in current_value:
                current_value = current_value[key]
            else:
                return None
        return current_value