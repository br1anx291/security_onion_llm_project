# # FILE: collectors/conn_collector.py

# import json
# from typing import List, Dict, Any

# class ConnCollector:
#     """
#     Collector chuyên phân tích các bản ghi conn.log đã được lọc sẵn
#     để trích xuất metadata và các tín hiệu bất thường của kết nối.
#     """
#     # 1. Thêm property collector_name
#     @property
#     def collector_name(self) -> str:
#         return "conn"

    
#     # 3. Tạo phương thức collect mới
#     def collect(self, log_lines: List[str]) -> Dict[str, Any] | None:
#         """
#         Phân tích các dòng conn.log để trích xuất trạng thái cuối cùng và các tín hiệu.
#         """
#         if not log_lines:
#             return None

#         # Lấy thông tin từ dòng log cuối cùng, đại diện cho trạng thái cuối của kết nối
#         try:
#             last_log_entry = json.loads(log_lines[-1])
#         except (json.JSONDecodeError, IndexError):
#             return None

#         # --- Logic mới để phân tích Data Flow ---
#         orig_bytes = last_log_entry.get('orig_bytes', 0) or 0
#         resp_bytes = last_log_entry.get('resp_bytes', 0) or 0
        
#         data_flow_analysis = "Symmetrical Traffic" # Mặc định
#         # Đặt ra ngưỡng chênh lệch (ví dụ: 5 lần) để tránh nhiễu
#         SIGNIFICANT_RATIO = 5 

#         # Kiểm tra xem có phải tuồn dữ liệu không
#         if orig_bytes > resp_bytes * SIGNIFICANT_RATIO:
#             orig_kb = round(orig_bytes / 1024, 2)
#             resp_kb = round(resp_bytes / 1024, 2)
#             data_flow_analysis = f"Data Exfiltration Pattern ({orig_kb}KB sent vs {resp_kb}KB received)"
        
#         # Kiểm tra xem có phải tải payload không
#         elif resp_bytes > orig_bytes * SIGNIFICANT_RATIO:
#             resp_kb = round(resp_bytes / 1024, 2)
#             data_flow_analysis = f"Payload Download Pattern ({resp_kb}KB downloaded)"
        
#         # --- Kết thúc logic mới ---
        
#         # Trích xuất các thông tin metadata quan trọng
#         duration = last_log_entry.get('duration')
#         conn_state = last_log_entry.get('conn_state')
#         history = last_log_entry.get('history')
#         service = last_log_entry.get('service')

#         # Tạo tín hiệu mới dựa trên metadata
#         scan_detected = False
#         connection_anomaly = None
        
#         # Logic phát hiện scan dựa trên history
#         if history in ('S', 'ShR', 'R'):
#             scan_detected = True

#         # Logic phát hiện trạng thái kết nối bất thường
#         if conn_state in ('S0', 'S1', 'S2', 'S3', 'REJ'):
#             connection_anomaly = f"Abnormal state: {conn_state}"

#         # Trả về dictionary kết quả
#         output: Dict[str, Any] = {
#             "duration": duration,
#             # "data_flow_analysis": data_flow_analysis, # Đây là tín hiệu mới của mày,
#             "orig_bytes" : orig_bytes, 
#             "resp_bytes": resp_bytes,
#             "conn_state": conn_state,
#             "service": service,
#         }
        
#         if scan_detected:
#             output["scan_detected"] = scan_detected
#         if connection_anomaly:
#             output["connection_anomaly"] = connection_anomaly

#         return output       

# FILE: collectors/conn_collector.py

import json
from typing import List, Dict, Any
from .base_collector import BaseCollector # <-- SỬA LỖI 1: Thêm kế thừa

class ConnCollector(BaseCollector): 
    """
    Collector chuyên phân tích các bản ghi conn.log đã được lọc sẵn
    để trích xuất metadata và các tín hiệu bất thường của kết nối.
    """
    CONN_STATE_DESCRIPTIONS = {
        'S0': 'Stealth Scan Attempt (S0)', 'S1': 'Half Open Scan (S1)',
        'S2': 'Suspicious Connection (S2)', 'S3': 'No Response From Server (S3)',
        'REJ': 'Connection Rejected (REJ)', 'SF': 'Normal Connection (SF)',
        'RSTO': 'Reset by Originator (RSTO)', 'RSTR': 'Reset by Responder (RSTR)',
    }
    
    # CSDL các mẫu history và phân tích tương ứng
    HISTORY_PATTERNS = {
        "S": {"label": "SYN Scan or Silent Drop", "summary": "Only SYN sent, no response. Likely a stealth scan or silent drop.", "severity": "High"},
        "ShR": {"label": "Half-Open Scan (RST by Originator)", "summary": "Received SYN/ACK but originator sent RST. Classic half-open scan.", "severity": "High"},
        "SRA": {"label": "Immediate Rejection (RST by Responder)", "summary": "SYN sent, immediate RST from responder. Port likely closed or firewalled.", "severity": "High"},
        "ShADr": {"label": "Server Aborted After Data", "summary": "Full handshake, data exchange, then server issued RST. Possible IPS/IDS drop.", "severity": "High"},
        "ShA": {"label": "Handshake Only, No Data", "summary": "Handshake completed, but no data sent. May indicate probing.", "severity": "Medium"},
        "SAF": {"label": "Abrupt Close by Client", "summary": "Client performed handshake and closed connection quickly. Possible probe.", "severity": "Medium"},
        "ShADad": {"label": "Active Session, No Teardown", "summary": "Data flowed both ways, but no FINs. Connection possibly interrupted.", "severity": "Medium"},
        "ShADafgR": {"label": "Abrupt Client Reset After Graceful Teardown","summary": "Connection established, data sent, server initiated FIN, but client responded with RST instead of normal FIN. May indicate forced termination or evasion.","severity": "Medium"},
        "ShAD": {"label": "Client Data Sent", "summary": "Client sent data, no response or teardown yet. Normal part of a flow.", "severity": "Informational"},
        "ShAd": {"label": "Server Data Response", "summary": "Server responded with data without client payload. Normal behavior.", "severity": "Informational"},
        # Thêm các mẫu khác vào đây nếu cần
    }
    NORMAL_HISTORY = {"ShADadfF", "ShADadGfF", "SADadfF", "ShADaggdgF", "ShADagdgTFf"}
    
    @property
    def collector_name(self) -> str:
        return "conn"


    def _interpret_history(self, history: str | None) -> Dict[str, str] | None:
        """Tra cứu và trả về phân tích chi tiết cho một history string."""
        if not history:
            return None 

        # 1. Ưu tiên check các pattern nguy hiểm trước
        if history in self.HISTORY_PATTERNS:
            return self.HISTORY_PATTERNS[history]

        # 2. Nếu không, check xem có phải là pattern bình thường không
        if history in self.NORMAL_HISTORY:
            return {
                "label": "Normal Full Connection",
                "summary": "A standard TCP session with a complete handshake, data transfer, and graceful teardown.",
                "severity": "Informational"
            }

        # 3. Nếu không thuộc cả hai, coi như là pattern lạ
        return {
            "label": "Unrecognized Pattern",
            "summary": f"The history string '{history}' does not have a predefined analysis. Requires manual review.",
            "severity": "Informational"
        }

    def collect(self, log_lines: List[str]) -> Dict[str, Any] | None:
        """
        Phân tích các dòng conn.log để trích xuất trạng thái cuối cùng và các tín hiệu.
        """
        if not log_lines:
            return None

        try:
            # Lấy thông tin từ dòng log cuối cùng
            last_log_entry = json.loads(log_lines[-1])
        except (json.JSONDecodeError, IndexError):
            return None

        # --- PHẦN 1: Trích xuất metadata gốc ---
        source_ip = last_log_entry.get('id.orig_h')
        source_port = last_log_entry.get('id.orig_p')
        dest_ip = last_log_entry.get('id.resp_h')
        dest_port = last_log_entry.get('id.resp_p')
        
        if local_orig := last_log_entry.get('local_orig', False) and not last_log_entry.get('local_resp', False):
            direction = "Egress"
        elif not last_log_entry.get('local_orig', False) and (local_resp := last_log_entry.get('local_resp', False)):
            direction = "Ingress"
        elif local_orig and local_resp:
            direction = "Lateral"
        else:
            direction = "Unknown"

        identity: List[Dict[str, Any]] = []
        identity = {
            "source": f"{source_ip} : {source_port}",
            "destination": f"{dest_ip} : {dest_port}",
            "traffic_direction": direction,
            "service": last_log_entry.get('service'),
            "transport_protocol": last_log_entry.get('proto'),
        }


        conn_state = last_log_entry.get('conn_state')
        history = last_log_entry.get('history')
        duration = last_log_entry.get('duration')
        orig_bytes = last_log_entry.get('orig_bytes', 0)
        resp_bytes = last_log_entry.get('resp_bytes', 0)
        
        connection_state_summary = self.CONN_STATE_DESCRIPTIONS.get(conn_state, f"Unknown State ({conn_state})")
        history_analysis = self._interpret_history(history)
        
        behavior: List[Dict[str, Any]] = []
        behavior = {
            "connection_state": connection_state_summary,
            # "history_analysis": history_analysis, # Tích hợp phân tích mới
            "duration_sec": round(duration, 4) if duration else 0.0,
        }
        
        # --- PHẦN 2: Phân tích và tạo ra các tín hiệu ---
        asymmetric_traffic_details: Dict[str, Any] | None = None
        SIGNIFICANT_RATIO = 5 

        # Logic phân tích traffic bất đối xứng
        if orig_bytes > resp_bytes * SIGNIFICANT_RATIO and resp_bytes > 0:
            ratio = round(orig_bytes / resp_bytes)
            asymmetric_traffic_details = {
                "direction": "upload",
                "ratio": ratio,
                "summary": f"Sent {round(orig_bytes/1024, 2)} KB, received {round(resp_bytes/1024, 2)} KB"
            }
        elif resp_bytes > orig_bytes * SIGNIFICANT_RATIO and orig_bytes > 0:
            ratio = round(resp_bytes / orig_bytes)
            asymmetric_traffic_details = {
                "direction": "download",
                "ratio": ratio,
                "summary": f"Received {round(resp_bytes/1024, 2)} KB, sent {round(orig_bytes/1024, 2)} KB"
            }

        # # CẢI TIẾN 3: Gắn thẻ (tagging) các hành vi bất thường
        # if history in ('S', 'ShR', 'R'):
        #     connection_tags.append({
        #         "finding_type": "scan_behavior",
        #         "summary": f"Potential Scan based on '{history}' history"
        #     })

        # # Tạo một mapping để code sạch hơn
        # CONN_STATE_DESCRIPTIONS = {
        #     'S0': 'Stealth Scan Attempt', 'S1': 'Half Open Scan',
        #     'S2': 'Suspicious Connection', 'S3': 'No Response From Server',
        #     'REJ': 'Connection Rejected'
        # }
        # if conn_state in CONN_STATE_DESCRIPTIONS:
        #     connection_tags.append({
        #         "finding_type": "abnormal_state",
        #         "summary": f"{conn_state}-{CONN_STATE_DESCRIPTIONS[conn_state]}" 
        #     })


        # connection_details = {
        #     "duration": duration,
        #     "service": last_log_entry.get('service'),
        #     "conn_state": conn_state,
        #     "history": history,
        #     "orig_bytes": orig_bytes,
        #     "resp_bytes": resp_bytes
        # }
        
        # Chuyển các kết quả phân tích thành một danh sách (list) các chuỗi
        if asymmetric_traffic_details:
            behavior["asymmetric_traffic_details"] = asymmetric_traffic_details

        # Trả về một dictionary với các key rõ ràng
        return {
            "identity": identity,
            "behavior": behavior
        }
