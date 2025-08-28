# FILE: collectors/conn_collector_revised.py

import json
from ipaddress import ip_address, ip_network
from typing import List, Dict, Any
from .base_collector import BaseCollector

class ConnCollector(BaseCollector):
    
    # --- THAY ĐỔI 1: Chuyển các mô tả sang dạng quan sát khách quan ---
    CONN_STATE_OBSERVATIONS = {
        'S0': 'Connection Attempt, No Reply',
        'S1': 'Handshake Started, Closed by Client Before Completion',
        'S2': 'Handshake Started, Closed by Server Before Completion',
        'S3': 'Handshake Started, No Final ACK from Client',
        'REJ': 'Connection Rejected by Server',
        'SF': 'Connection Established and Fully Closed',
        'RSTO': 'Connection Closed by Client (RST)',
        'RSTR': 'Connection Closed by Server (RST)',
    }
    
    # --- THAY ĐỔI 2: Thêm các dải mạng riêng đã biết để kiểm tra hướng traffic ---
    PRIVATE_IP_RANGES = [
        ip_network('10.0.0.0/8'),
        ip_network('172.16.0.0/12'),
        ip_network('192.168.0.0/16'),
        ip_network('127.0.0.0/8'),
        ip_network('169.254.0.0/16'),
    ]

    @property
    def collector_name(self) -> str: return "conn"

    # --- THAY ĐỔI 3: Hàm kiểm tra IP riêng tư, đáng tin cậy hơn ---
    def _is_private_ip(self, ip_str: str) -> bool:
        if not ip_str: return False
        try:
            ip = ip_address(ip_str)
            return ip.is_private
        except ValueError:
            return False

    def collect(self, log_lines: List[str]) -> Dict[str, Any] | None:
        if not log_lines: return None
        try:
            # Chỉ cần phân tích bản ghi cuối cùng của phiên kết nối
            last_log_entry = json.loads(log_lines[-1])
        except (json.JSONDecodeError, IndexError):
            return None

        # --- PHẦN 1: IDENTITY VÀ LOGIC TRAFFIC_DIRECTION MỚI ---
        source_ip = last_log_entry.get('id.orig_h')
        dest_ip = last_log_entry.get('id.resp_h')
        
        # Logic traffic_direction mới, không phụ thuộc vào cấu hình Zeek
        is_source_private = self._is_private_ip(source_ip)
        is_dest_private = self._is_private_ip(dest_ip)

        if is_source_private and not is_dest_private: direction = "Egress"       # Nội bộ -> Internet
        elif not is_source_private and is_dest_private: direction = "Ingress"      # Internet -> Nội bộ
        elif is_source_private and is_dest_private: direction = "Lateral"        # Nội bộ -> Nội bộ
        else: direction = "Internet-to-Internet" # Internet -> Internet (ví dụ proxy)
        
        identity = {
            "source_ip": source_ip, "source_port": last_log_entry.get('id.orig_p'),
            "destination_ip": dest_ip, "destination_port": last_log_entry.get('id.resp_p'),
            "traffic_direction": direction,
            "service": last_log_entry.get('service'),
            "transport_protocol": last_log_entry.get('proto'),
        }

        # --- PHẦN 2: XÂY DỰNG KHỐI ANALYSIS KHÁCH QUAN HƠN ---
        conn_state = last_log_entry.get('conn_state')
        orig_bytes = last_log_entry.get('orig_bytes', 0)
        resp_bytes = last_log_entry.get('resp_bytes', 0)
        
        # Đưa ra đánh giá tổng thể dựa trên các bằng chứng
        assessment = "Informational: Standard connection recorded."
        if conn_state in ('S0', 'S1', 'S2', 'S3', 'REJ'):
            assessment = f"Suspicious Anomaly: Connection failed to establish with state '{conn_state}', which can be indicative of scanning or probing activity."
        
        analysis = {
            "overall_assessment": assessment,
            "observed_connection_state": self.CONN_STATE_OBSERVATIONS.get(conn_state, f"Unknown State ({conn_state})"),
            "observed_flow_ratio": {
                "upload_bytes": orig_bytes,
                "download_bytes": resp_bytes,
                "ratio": round(orig_bytes / resp_bytes, 1) if resp_bytes > 0 else "N/A"
            }
        }
        
        statistics = { "duration_sec": round(last_log_entry.get('duration', 0.0), 4) }

        return {
            "identity": identity,
            "analysis": analysis,
            "statistics": statistics
        }