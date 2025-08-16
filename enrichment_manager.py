# security_onion_llm_project/enrichment_manager.py

import subprocess
import json
import logging
import os
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
from collectors.ssl_collector import SslCollector


LOG_FORMAT = "%(asctime)s [%(threadName)-12.12s] [%(levelname)-5.5s]  %(message)s"
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)

class EnrichmentManager:
    
    # *** THAY ĐỔI 1: Cấu trúc lại hoàn toàn SIGNAL_CLASSIFICATION ***
    # Mỗi quy tắc bây giờ là một object mô tả rõ ràng cách kiểm tra.
    SIGNAL_CLASSIFICATION = {
        "CRITICAL": [
            # HTTP: 
            # User agent có dấu hiệu dị thường, độc hại.
            {"collector": "http", "path": "analysis.user_agent_category", "check": "equals", "value": "Anomalous/Malformed"},
            {"collector": "http", "path": "analysis.file_transfer_risk", "check": "startswith", "value": "Suspicious Upload"},
            
            # DNS: 
            # Kết hợp cả 2 hành vi nguy hiểm nhất: DGA và Beaconing.
            {"collector": "dns", "path": "analysis.query_pattern", "check": "equals", "value": "Repetitive Beaconing & DGA Detected"},
            
            # FILES: Mức độ nghiêm trọng tổng thể của phiên được đánh giá là Critical.
            # Thường xảy ra khi một file có nhiều chỉ số rủi ro cao kết hợp (ví dụ: vừa né tránh, vừa là file thực thi).
            {"collector": "files", "path": "analysis.highest_threat_level", "check": "equals", "value": "Critical"},
            # Quy tắc này phát hiện một file có điểm rủi ro cực kỳ cao. bắt các trường hợp riêng lẻ đặc biệt nguy hiểm.
            {"collector": "files", "path": "evidence.findings[*].risk_score", "check": "gte", "value": 90},
            
            # SSL: 
            # Dấu vân tay client (JA3) khớp với CSDL mã độc đã biết
            {"collector": "ssl", "path": "analysis.ja3_threat_match", "check": "startswith", "value": "JA3 Matched Malware:"},
            # SSL: Dấu vân tay server (JA3S) khớp với CSDL C2 đã biết.
            {"collector": "ssl", "path": "analysis.ja3s_threat_match", "check": "startswith", "value": "JA3S Matched C2 Server:"},
        ],
        "HIGH": [
            # CONN: Phân tích history cho thấy các hành vi quét mạng hoặc tấn công rõ ràng.
            {"collector": "conn", "path": "analysis.history_analysis.severity", "check": "equals", "value": "High"},
            # HTTP: Phát hiện nội dung thực thi được tải về.
            {"collector": "http", "path": "analysis.download_risk", "check": "equals", "value": "Executable Content Detected"},
            # HTTP: Kết nối thẳng đến địa chỉ IP.
            {"collector": "http", "path": "analysis.destination_analysis", "check": "equals", "value": "Direct-to-IP Connection"},
            # HTTP: User agent là các công cụ dòng lệnh hoặc script.
            {"collector": "http", "path": "analysis.user_agent_category", "check": "equals", "value": "Scripting/Tool"},
            {"collector": "http", "path": "analysis.content_risk", "check": "equals", "value": "Suspicious Content Detected"},
            {"collector": "http", "path": "analysis.file_transfer_risk", "check": "startswith", "value": "Suspicious Download"},
            
            # SSL: 
            # Chứng chỉ có vấn đề nghiêm trọng (hết hạn, tự ký, không tin cậy).
            {"collector": "ssl", "path": "analysis.certificate_status", "check": "startswith", "value": "Invalid"},
                    
            # DNS: 
            # Phát hiện DGA
            { "collector": "dns", "path": "analysis.query_pattern", "check": "equals", "value": "DGA Detected"},
            # DNS: Phát hiện beaconing
            { "collector": "dns", "path": "analysis.query_pattern", "check": "equals", "value": "Repetitive Beaconing Detected"},
            
            # FILES: 
            # Phát hiện có kỹ thuật né tránh được sử dụng.
            {"collector": "files", "path": "analysis.evasion_techniques_detected", "check": "equals", "value": "Yes"}, 
            # Có một file bị phát hiện có lý do là MIME Mismatch. Dấu hiệu của việc ngụy trang file 
            {"collector": "files", "path": "evidence.findings[*].reasons", "check": "contains", "value": "MIME_MISMATCH"},
            # Có một file bị phát hiện có entropy cao. Dấu hiệu của mã độc đã được mã hóa hoặc "pack" lại.
            {"collector": "files", "path": "evidence.findings[*].reasons", "check": "contains", "value": "HIGH_ENTROPY"},
        ],
        "MEDIUM": [
            # CONN: Phân tích history cho thấy các hành vi đáng ngờ như probing.
            {"collector": "conn", "path": "analysis.history_analysis.severity", "check": "equals", "value": "Medium"},

            # HTTP: User agent là trình duyệt quá cũ.
            {"collector": "http", "path": "analysis.user_agent_category", "check": "equals", "value": "Outdated Browser"},
            {"collector": "http", "path": "statistics.client_error_ratio", "check": "gte", "value": 0.7},
            {"collector": "http", "path": "analysis.transfer_volume", "check": "equals", "value": "Large"},
            
            
            # DNS: 
            # Tỷ lệ truy vấn thất bại cao. Có thể là DGA đang tìm C2 hoặc lỗi cấu hình.
            { "collector": "dns", "path": "analysis.query_integrity", "check": "equals", "value": "High Failure Ratio" },
            # Sử dụng các TLD thường bị lạm dụng.
            { "collector": "dns", "path": "analysis.tld_risk", "check": "equals", "value": "Suspicious TLDs Used" },
            
            # FILES: 
            # Có ít nhất một file đáng ngờ được phát hiện trong phiên.
            {"collector": "files", "path": "statistics.suspicious_files_count", "check": "gte", "value": 1},            
            #  Có file bị phát hiện vì có phần mở rộng đáng ngờ (ví dụ: .exe, .dll, .bat).
            {"collector": "files", "path": "evidence.findings[*].reasons", "check": "contains", "value": "SUSPICIOUS_EXTENSION"},
            #Có file bị phát hiện vì có loại MIME đáng ngờ.
            {"collector": "files", "path": "evidence.findings[*].reasons", "check": "contains", "value": "SUSPICIOUS_MIME"},

            # SSL: 
            # Sử dụng giao thức hoặc bộ mật mã yếu
            {"collector": "ssl", "path": "analysis.encryption_strength", "check": "startswith", "value": "Weak"},
            # Tên miền máy chủ (SNI) bị phân loại là Adware/Tracker.
            {"collector": "ssl", "path": "analysis.server_reputation", "check": "equals", "value": "Adware/Tracker"},
        ],
        "LOW": [
            # DNS: Phát hiện TTL thấp
            {"collector": "dns","path": "analysis.ttl_behavior","check": "equals","value": "Low TTL Detected"},
            # SSL: Bắt tay (handshake) thất bại. Có thể do lỗi mạng hoặc cấu hình.
            {"collector": "ssl", "path": "analysis.handshake_status", "check": "equals", "value": "Failed"},
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

    # def _find_and_fetch_all_logs(self, suricata_alert: dict) -> Tuple[str | None, Dict[str, List[str]]]:
    #     log_cache = {}
    #     timestamp = self._extract_timestamp_from_alert(suricata_alert)
    #     if timestamp is None: 
    #         logging.warning("Exiting: Could not extract timestamp from alert.")
    #         return None, {}
        
    #     conn_log_files = []
        
    #     # 1. Ưu tiên tìm kiếm trong thư mục 'current'
    #     current_log_dir = os.path.join(ZEEK_LOGS_DIR, "current")
    #     if os.path.isdir(current_log_dir):
    #         logging.info(f"Đang tìm kiếm trong thư mục 'current': {current_log_dir}")
    #         try:
    #             # Tìm tất cả các file có dạng conn.*.log hoặc conn.log trong thư mục current
    #             for filename in os.listdir(current_log_dir):
    #                 if filename.startswith("conn.") and filename.endswith(".log"):
    #                     conn_log_files.append(os.path.join(current_log_dir, filename))
    #         except OSError as e:
    #             logging.error(f"Không thể truy cập thư mục 'current': {e}")

    #     # 2. Tìm kiếm trong các thư mục log lịch sử dựa trên timestamp
    #     historical_log_files = find_log_files(ZEEK_LOGS_DIR, "conn", timestamp)
        
    #     # 3. Kết hợp danh sách và loại bỏ các file trùng lặp
    #     conn_log_files.extend(historical_log_files)
    #     # Dùng set để loại bỏ trùng lặp, sau đó chuyển lại list và sắp xếp cho ổn định
    #     conn_log_files = sorted(list(set(conn_log_files)))
    #     # ********************
    #     all_raw_conn_lines = []
    #     community_id = suricata_alert.get("network", {}).get("community_id")
    #     if community_id:
    #         for log_file in conn_log_files:
    #             result = subprocess.run(['rg', '-z', f'"community_id":"{community_id}"', log_file], capture_output=True,text=True, check=False)
    #             if result.returncode <= 1 and result.stdout:            
    #                 normalized_output = result.stdout.replace('\0', '\n')        
    #                 lines = [line for line in normalized_output.strip().split('\n') if line]  
    #                 all_raw_conn_lines.extend(lines)

    #     if not all_raw_conn_lines:
    #         try:
    #             src_ip, src_port = suricata_alert['source']['ip'], suricata_alert['source']['port']
    #             dest_ip, dest_port = suricata_alert['destination']['ip'], suricata_alert['destination']['port']
    #             proto = suricata_alert.get('network', {}).get('transport', '').lower()
    #             if not proto:
    #                 proto = json.loads(suricata_alert['message']).get('proto', '').lower()
                    
    #             for log_file in conn_log_files:
    #                 p1 = subprocess.Popen(['rg', f'"id.orig_h":"{src_ip}"', log_file], stdout=subprocess.PIPE, text=True)
    #                 p2 = subprocess.Popen(['rg', f'"id.orig_p":{src_port}'], stdin=p1.stdout, stdout=subprocess.PIPE, text=True)
    #                 p3 = subprocess.Popen(['rg', f'"id.resp_h":"{dest_ip}"'], stdin=p2.stdout, stdout=subprocess.PIPE, text=True)
    #                 p4 = subprocess.Popen(['rg', f'"id.resp_p":{dest_port}'], stdin=p3.stdout, stdout=subprocess.PIPE, text=True)
    #                 p5 = subprocess.Popen(['rg', f'"proto":"{proto}"'], stdin=p4.stdout, stdout=subprocess.PIPE, text=True)
    #                 p1.stdout.close(); p2.stdout.close(); p3.stdout.close(); p4.stdout.close()
    #                 result_stdout, _ = p5.communicate()
    #                 if result_stdout: all_raw_conn_lines.extend(result_stdout.strip().split('\n'))
    #         except (KeyError, TypeError, json.JSONDecodeError): return None, {}
        
    #     time_relevant_candidates = []
    #     for line in all_raw_conn_lines:
    #         if not line or not line.strip():
    #             continue
    #         try:
    #             log_entry = json.loads(line)
    #             ts = float(log_entry.get('ts', 0))
    #             if abs(ts - timestamp) < CONN_LOG_TIME_WINDOW_SECONDS:
    #                 time_relevant_candidates.append(log_entry)
    #         except (json.JSONDecodeError, ValueError, TypeError) as e:
    #             logging.warning(f"Skipping malformed conn log line. Error: {e}. Line: '{line[:100]}...'")
    #             continue
        
    #     if not time_relevant_candidates: 
    #         return None, {}
    #     best_match = max(time_relevant_candidates, key=lambda x: float(x.get('duration', -1) or -1), default=None)
        
    #     uid = best_match.get('uid')
    #     if not uid: return None, {}
    #     log_cache['conn'] = [json.dumps(c) for c in time_relevant_candidates if c.get('uid') == uid]
        
    #     def _grep_worker(log_type: str) -> Tuple[str, List[str]]:
    #         log_files = find_log_files(ZEEK_LOGS_DIR, log_type, timestamp)
    #         if not log_files: return log_type, []
    #         matching_lines = []
    #         for log_file in log_files:
    #             result = subprocess.run(['rg', uid, log_file], capture_output=True, text=True, check=False)
    #             if result.returncode <= 1 and result.stdout: matching_lines.extend(result.stdout.strip().split('\n'))
    #         return log_type, matching_lines

    #     log_types_to_fetch = ['http', 'dns', 'ssl', 'files']
    #     with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
    #         future_to_log_type = {executor.submit(_grep_worker, log_type): log_type for log_type in log_types_to_fetch}
    #         for future in as_completed(future_to_log_type):
    #             log_type, result_lines = future.result()
    #             log_cache[log_type] = result_lines

    #     return uid, log_cache

    def _find_and_fetch_all_logs(self, suricata_alert: dict) -> Tuple[str | None, Dict[str, List[str]]]:
        log_cache = {}
        timestamp = self._extract_timestamp_from_alert(suricata_alert)
        if timestamp is None: 
            logging.warning("Exiting: Could not extract timestamp from alert.")
            return None, {}
        
        # Bước 1: Lấy các file log lịch sử dựa trên timestamp làm nguồn tìm kiếm chính
        historical_conn_files = find_log_files(ZEEK_LOGS_DIR, "conn", timestamp)
        if not historical_conn_files: 
            logging.warning(f"Warning: No historical conn.log files found for timestamp {timestamp}. Will check 'current' directory.")
            # Không thoát ngay, vì có thể fallback sang 5-tuple và tìm trong current sau
        
        all_raw_conn_lines = []
        community_id = suricata_alert.get("network", {}).get("community_id")

        # === LOGIC MỚI BẮT ĐẦU TẠI ĐÂY ===

        if community_id:
            # 1. Tìm kiếm community_id trong các file log lịch sử (theo timestamp) trước
            logging.info(f"Searching for community_id '{community_id}' in historical files: {historical_conn_files}")
            for log_file in historical_conn_files:
                result = subprocess.run(['rg', '-z', f'"community_id":"{community_id}"', log_file], capture_output=True,text=True, check=False)
                if result.returncode <= 1 and result.stdout:          
                    normalized_output = result.stdout.replace('\0', '\n')      
                    lines = [line for line in normalized_output.strip().split('\n') if line]  
                    all_raw_conn_lines.extend(lines)

            # 2. NẾU KHÔNG TÌM THẤY, mới tìm kiếm dự phòng trong thư mục 'current'
            if not all_raw_conn_lines:
                logging.info(f"Community_id not found in historical logs. Falling back to 'current' directory.")
                current_log_dir = os.path.join(ZEEK_LOGS_DIR, "current")
                if os.path.isdir(current_log_dir):
                    for filename in os.listdir(current_log_dir):
                        if filename.startswith("conn.") and filename.endswith(".log"):
                            current_log_file = os.path.join(current_log_dir, filename)
                            logging.info(f"Scanning file: {current_log_file}")
                            result = subprocess.run(['rg', '-z', f'"community_id":"{community_id}"', current_log_file], capture_output=True,text=True, check=False)
                            if result.returncode <= 1 and result.stdout:
                                normalized_output = result.stdout.replace('\0', '\n')      
                                lines = [line for line in normalized_output.strip().split('\n') if line]  
                                all_raw_conn_lines.extend(lines)
        
        # === KẾT THÚC LOGIC MỚI ===

        if not all_raw_conn_lines:
            # Nếu tìm bằng community_id thất bại, fallback sang 5-tuple
            # Logic này sẽ chỉ tìm trong các file lịch sử để đảm bảo tính nhất quán
            logging.info("Community_id search failed. Falling back to 5-tuple search in historical logs.")
            try:
                src_ip, src_port = suricata_alert['source']['ip'], suricata_alert['source']['port']
                dest_ip, dest_port = suricata_alert['destination']['ip'], suricata_alert['destination']['port']
                proto = suricata_alert.get('network', {}).get('transport', '').lower()
                if not proto:
                    proto = json.loads(suricata_alert['message']).get('proto', '').lower()
                    
                for log_file in historical_conn_files: # CHỈ TÌM TRONG FILE LỊCH SỬ
                    p1 = subprocess.Popen(['rg', f'"id.orig_h":"{src_ip}"', log_file], stdout=subprocess.PIPE, text=True)
                    p2 = subprocess.Popen(['rg', f'"id.orig_p":{src_port}'], stdin=p1.stdout, stdout=subprocess.PIPE, text=True)
                    p3 = subprocess.Popen(['rg', f'"id.resp_h":"{dest_ip}"'], stdin=p2.stdout, stdout=subprocess.PIPE, text=True)
                    p4 = subprocess.Popen(['rg', f'"id.resp_p":{dest_port}'], stdin=p3.stdout, stdout=subprocess.PIPE, text=True)
                    p5 = subprocess.Popen(['rg', f'"proto":"{proto}"'], stdin=p4.stdout, stdout=subprocess.PIPE, text=True)
                    p1.stdout.close(); p2.stdout.close(); p3.stdout.close(); p4.stdout.close()
                    result_stdout, _ = p5.communicate()
                    if result_stdout: all_raw_conn_lines.extend(result_stdout.strip().split('\n'))
            except (KeyError, TypeError, json.JSONDecodeError): return None, {}
        
        # Phần còn lại của hàm giữ nguyên
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
            logging.warning("No time-relevant conn log entries found after searching.")
            return None, {}
        best_match = max(time_relevant_candidates, key=lambda x: float(x.get('duration', -1) or -1), default=None)
        
        if not best_match: return None, {}
        
        uid = best_match.get('uid')
        if not uid: return None, {}
        log_cache['conn'] = [json.dumps(c) for c in time_relevant_candidates if c.get('uid') == uid]
        
        def _grep_worker(log_type: str) -> Tuple[str, List[str]]:
            # Worker này vẫn nên tìm trong log lịch sử để lấy đúng context
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
