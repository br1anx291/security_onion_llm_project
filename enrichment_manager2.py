# security_onion_llm_project/enrichment_manager.py

import subprocess
import json
import logging
from datetime import datetime
from typing import Dict, Any, Tuple, List
from concurrent.futures import ThreadPoolExecutor, as_completed
from elasticsearch import Elasticsearch
from config import ZEEK_LOGS_DIR, CONN_LOG_TIME_WINDOW_SECONDS, MAX_WORKERS
from log_helper import find_log_files
from collectors.conn2_collector import ConnCollector
from collectors.dns_collector import DnsCollector
from collectors.http2_collector import HttpCollector
from collectors.files_collector import FilesCollector
from collectors.ssl2_collector import SslCollector

LOG_FORMAT = "%(asctime)s [%(threadName)-12.12s] [%(levelname)-5.5s]  %(message)s"
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)

class EnrichmentManager:
    
    # *** THAY ĐỔI 1: Cấu trúc lại hoàn toàn SIGNAL_CLASSIFICATION ***
    # Mỗi quy tắc bây giờ là một object mô tả rõ ràng cách kiểm tra.
    SIGNAL_CLASSIFICATION = {
        "CRITICAL": [
            # SSL: Phát hiện JA3 trùng khớp với CSDL mã độc nội bộ.
            {"collector": "ssl", "path": "analysis.ja3_threat_match", "check": "startswith", "value": "JA3 Matched Malware Watchlist"},
            # HTTP: User agent có dấu hiệu dị thường, độc hại.
            {"collector": "http", "path": "analysis.user_agent_category", "check": "equals", "value": "Anomalous/Malformed"},
        ],
        "HIGH": [
            # CONN: Phân tích history cho thấy các hành vi quét mạng hoặc tấn công rõ ràng.
            {"collector": "conn", "path": "analysis.history_analysis.severity", "check": "equals", "value": "High"},
            # SSL: Chứng chỉ có vấn đề nghiêm trọng (hết hạn, tự ký, không tin cậy).
            {"collector": "ssl", "path": "analysis.certificate_status", "check": "startswith", "value": "Invalid"},
            # DNS: Truy vấn có entropy cao, một dấu hiệu mạnh của DGA.
            {"collector": "dns", "path": "analysis.query_risks", "check": "contains", "value": "High Entropy (DGA?)"},
            # FILES: Phát hiện có file đáng ngờ (dựa trên MIME/đuôi tệp) trong phiên.
            {"collector": "files", "path": "analysis.session_risk", "check": "equals", "value": "Suspicious Files Detected"},
            # HTTP: Phát hiện nội dung thực thi được tải về.
            {"collector": "http", "path": "analysis.download_risk", "check": "equals", "value": "Executable Content Detected"},
            # HTTP: Kết nối thẳng đến địa chỉ IP.
            {"collector": "http", "path": "analysis.destination_analysis", "check": "startswith", "value": "Direct-to-IP"},
            # HTTP: User agent là các công cụ dòng lệnh hoặc script.
            {"collector": "http", "path": "analysis.user_agent_category", "check": "equals", "value": "Scripting/Tool"},
        ],
        "MEDIUM": [
            # CONN: Phân tích history cho thấy các hành vi đáng ngờ như probing.
            {"collector": "conn", "path": "analysis.history_analysis.severity", "check": "equals", "value": "Medium"},
            # SSL: Sử dụng giao thức hoặc bộ mật mã yếu.
            {"collector": "ssl", "path": "analysis.encryption_strength", "check": "startswith", "value": "Weak"},
            # DNS: Tỷ lệ truy vấn thất bại cao.
            {"collector": "dns", "path": "statistics.failed_queries_ratio", "check": "gte", "value": 0.5},
            # DNS: Phát hiện truy vấn dài hoặc có TLD đáng ngờ.
            {"collector": "dns", "path": "analysis.query_risks", "check": "contains", "value": "Long Query"},
            {"collector": "dns", "path": "analysis.query_risks", "check": "contains", "value": "Suspicious TLD"},
            # HTTP: Phát hiện URI có đuôi file đáng ngờ.
            {"collector": "http", "path": "analysis.uri_risk", "check": "equals", "value": "Suspicious Extension Found"},
            # HTTP: User agent là trình duyệt quá cũ.
            {"collector": "http", "path": "analysis.user_agent_category", "check": "equals", "value": "Outdated Browser"},
        ],
        "LOW": [
            # DNS: Phát hiện TTL thấp.
            {"collector": "dns", "path": "analysis.low_ttl_analysis", "check": "startswith", "value": "Low TTL Detected"},
            # DNS: Phát hiện loại truy vấn đáng ngờ.
            {"collector": "dns", "path": "analysis.suspicious_qtype_analysis", "check": "equals", "value": "Suspicious QTYPE Found"},
        ]
    }

    def __init__(self):
        self.all_collectors = [
            HttpCollector(ZEEK_LOGS_DIR), DnsCollector(ZEEK_LOGS_DIR),
            FilesCollector(ZEEK_LOGS_DIR), SslCollector(ZEEK_LOGS_DIR),
            ConnCollector(ZEEK_LOGS_DIR)
        ]
        self.collectors_map = {c.collector_name: c for c in self.all_collectors}

    # *** THAY ĐỔI 2: Thêm hàm helper để lấy giá trị nested ***
    def _get_nested_value(self, data: Dict[str, Any], path: str) -> Any:
        """Lấy giá trị từ dictionary lồng nhau bằng chuỗi path (ví dụ: 'a.b.c')."""
        keys = path.split('.')
        current_value = data
        for key in keys:
            if isinstance(current_value, dict) and key in current_value:
                current_value = current_value[key]
            else:
                return None
        return current_value

    # *** THAY ĐỔI 3: Viết lại hoàn toàn hàm _classify_evidence ***
    def _classify_evidence(self, all_evidence: Dict[str, Any]) -> Tuple[Dict, Dict, Dict, Dict, Dict]:
        critical_evidence, high_evidence, medium_evidence, low_evidence = {}, {}, {}, {}
        reference_evidence = {}
        classified_collectors = set()

        for severity, rules in self.SIGNAL_CLASSIFICATION.items():
            for rule in rules:
                collector_name = rule["collector"]
                # Bỏ qua nếu collector này đã được phân loại ở mức cao hơn
                if collector_name in classified_collectors:
                    continue

                data = all_evidence.get(collector_name)
                if not data:
                    continue

                path = rule["path"]
                check_type = rule["check"]
                actual_value = self._get_nested_value(data, path)

                match_found = False
                if check_type == "exists" and actual_value is not None:
                    match_found = True
                elif check_type == "equals" and actual_value == rule["value"]:
                    match_found = True
                elif check_type == "gte" and isinstance(actual_value, (int, float)) and actual_value >= rule["value"]:
                    match_found = True
                elif check_type == "startswith" and isinstance(actual_value, str) and actual_value.startswith(rule["value"]):
                    match_found = True
                elif check_type == "any_item_startswith" and isinstance(actual_value, list):
                    nested_path = rule["nested_path"]
                    nested_value = rule["nested_value"]
                    for item in actual_value:
                        item_val = self._get_nested_value(item, nested_path)
                        if isinstance(item_val, str) and item_val.startswith(nested_value):
                            match_found = True
                            break

                if match_found:
                    if severity == "CRITICAL":
                        critical_evidence[collector_name] = data
                    elif severity == "HIGH":
                        high_evidence[collector_name] = data
                    elif severity == "MEDIUM":
                        medium_evidence[collector_name] = data
                    elif severity == "LOW":
                        low_evidence[collector_name] = data
                    classified_collectors.add(collector_name)
        
        # Thêm các bằng chứng không được phân loại vào mục tham khảo
        for collector_name, data in all_evidence.items():
            if data and collector_name not in classified_collectors:
                reference_evidence[collector_name] = data

        return (critical_evidence, high_evidence, medium_evidence, low_evidence, reference_evidence)

    # Các hàm còn lại giữ nguyên, không cần thay đổi
    def _extract_timestamp_from_alert(self, alert: dict) -> float | None:
        try:
            message_data = json.loads(alert['message'])
            ts_str_raw = message_data['timestamp']
            ts_str_normalized = ts_str_raw.replace('Z', '+00:00').replace('+0000', '+00:00')
            return datetime.fromisoformat(ts_str_normalized).timestamp()
        except (KeyError, TypeError, json.JSONDecodeError, ValueError):
            return None

    def _find_and_fetch_all_logs(self, suricata_alert: dict) -> Tuple[str | None, Dict[str, List[str]]]:
        log_cache = {}
        timestamp = self._extract_timestamp_from_alert(suricata_alert)
        if timestamp is None: 
            logging.warning("Exiting: Could not extract timestamp from alert.")
            return None, {}
        
        conn_log_files = find_log_files(ZEEK_LOGS_DIR, "conn", timestamp)
        if not conn_log_files: 
            logging.warning(f"Exiting: No conn.log files found for timestamp {timestamp}.")
            return None, {}
        
        all_raw_conn_lines = []
        community_id = suricata_alert.get("network", {}).get("community_id")
        if community_id:
            for log_file in conn_log_files:
                result = subprocess.run(['rg', '-z', f'"community_id":"{community_id}"', log_file], capture_output=True,text=True, check=False)
                if result.returncode <= 1 and result.stdout:            
                    normalized_output = result.stdout.replace('\0', '\n')        
                    lines = [line for line in normalized_output.strip().split('\n') if line]  
                    all_raw_conn_lines.extend(lines)

        if not all_raw_conn_lines:
            try:
                src_ip, src_port = suricata_alert['source']['ip'], suricata_alert['source']['port']
                dest_ip, dest_port = suricata_alert['destination']['ip'], suricata_alert['destination']['port']
                proto = suricata_alert.get('network', {}).get('transport', '').lower()
                if not proto:
                    proto = json.loads(suricata_alert['message']).get('proto', '').lower()
                    
                for log_file in conn_log_files:
                    p1 = subprocess.Popen(['rg', f'"id.orig_h":"{src_ip}"', log_file], stdout=subprocess.PIPE, text=True)
                    p2 = subprocess.Popen(['rg', f'"id.orig_p":{src_port}'], stdin=p1.stdout, stdout=subprocess.PIPE, text=True)
                    p3 = subprocess.Popen(['rg', f'"id.resp_h":"{dest_ip}"'], stdin=p2.stdout, stdout=subprocess.PIPE, text=True)
                    p4 = subprocess.Popen(['rg', f'"id.resp_p":{dest_port}'], stdin=p3.stdout, stdout=subprocess.PIPE, text=True)
                    p5 = subprocess.Popen(['rg', f'"proto":"{proto}"'], stdin=p4.stdout, stdout=subprocess.PIPE, text=True)
                    p1.stdout.close(); p2.stdout.close(); p3.stdout.close(); p4.stdout.close()
                    result_stdout, _ = p5.communicate()
                    if result_stdout: all_raw_conn_lines.extend(result_stdout.strip().split('\n'))
            except (KeyError, TypeError, json.JSONDecodeError): return None, {}
        
        time_relevant_candidates = []
        for line in all_raw_conn_lines:
            if not line or not line.strip():
                continue
            try:
                log_entry = json.loads(line)
                ts = float(log_entry.get('ts', 0))
                if abs(ts - timestamp) < CONN_LOG_TIME_WINDOW_SECONDS:
                    time_relevant_candidates.append(log_entry)
            except (json.JSONDecodeError, ValueError, TypeError) as e:
                logging.warning(f"Skipping malformed conn log line. Error: {e}. Line: '{line[:100]}...'")
                continue
        
        if not time_relevant_candidates: 
            return None, {}
        best_match = max(time_relevant_candidates, key=lambda x: float(x.get('duration', -1) or -1), default=None)
        
        uid = best_match.get('uid')
        if not uid: return None, {}
        log_cache['conn'] = [json.dumps(c) for c in time_relevant_candidates if c.get('uid') == uid]
        
        def _grep_worker(log_type: str) -> Tuple[str, List[str]]:
            log_files = find_log_files(ZEEK_LOGS_DIR, log_type, timestamp)
            if not log_files: return log_type, []
            matching_lines = []
            for log_file in log_files:
                result = subprocess.run(['rg', uid, log_file], capture_output=True, text=True, check=False)
                if result.returncode <= 1 and result.stdout: matching_lines.extend(result.stdout.strip().split('\n'))
            return log_type, matching_lines

        log_types_to_fetch = ['http', 'dns', 'ssl', 'files']
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            future_to_log_type = {executor.submit(_grep_worker, log_type): log_type for log_type in log_types_to_fetch}
            for future in as_completed(future_to_log_type):
                log_type, result_lines = future.result()
                log_cache[log_type] = result_lines

        return uid, log_cache

    def _build_json_output(self, alert: dict, conn_data: dict | None,
                           critical_evidence: dict, high_evidence: dict,
                           medium_evidence: dict, low_evidence: dict,
                           reference_evidence: dict) -> Dict[str, Any]:
        rule_info = alert.get('rule', {})
        metadata = rule_info.get('metadata', {})
        event_info = alert.get('event', {})
        alert_output = {
            "signature": rule_info.get('name', 'N/A'),
            "category": rule_info.get('category', 'N/A'),
            # "rule_severity": metadata.get('signature_severity', ['N/A'])[0],
            # "rule_confidence": metadata.get('confidence', ['N/A'])[0],
            # "event_severity": event_info.get('severity_label', 'N/A').upper(),
            "timestamp": alert.get('@timestamp', 'N/A')
        }

        conn_output = {}
        if conn_data:
            if conn_data.get('identity'):
                conn_output['identity'] = conn_data['identity']
            if conn_data.get('statistics'):
                conn_output['statistics'] = conn_data['statistics']
            if conn_data.get('analysis'):
                conn_output['analysis'] = conn_data['analysis']
      
        # *** BẮT ĐẦU THAY ĐỔI ***
        # 3. Tạo object evidence một cách linh hoạt
        # Khởi tạo một dictionary rỗng
        evidence_output = {}
        # Chỉ thêm các mức độ (severity) nếu chúng có chứa bằng chứng
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
        
        # 4. Tạo cấu trúc JSON cuối cùng
        final_output = {
            "alert": alert_output,
        }
        if conn_output:
            final_output["connection"] = conn_output
        # Chỉ thêm khối "evidence" vào output cuối cùng nếu nó không rỗng
        if evidence_output:
            final_output["evidence"] = evidence_output
        # *** KẾT THÚC THAY ĐỔI ***

        return final_output

    def enrich_and_prompt(self, suricata_alert: dict) -> Dict[str, Any]:
        uid, log_cache = self._find_and_fetch_all_logs(suricata_alert)
        
        if not uid:
            return self._build_json_output(suricata_alert, None, {}, {}, {}, {}, {})
        
        conn_collector = self.collectors_map['conn']
        conn_evidence = conn_collector.collect(log_cache.get('conn', []))
        
        all_other_evidence = {}
        other_collectors = [c for c in self.all_collectors if c.collector_name != 'conn']
        
        for collector in other_collectors:
            result = collector.collect(log_cache.get(collector.collector_name, []))
            if result:
                all_other_evidence[collector.collector_name] = result
                      
        classified_evidence = self._classify_evidence(all_other_evidence)
        
        return self._build_json_output(suricata_alert, conn_evidence, *classified_evidence)