# FILE: collectors/conn_collector.py

import json
from typing import List, Dict, Any
from .base_collector import BaseCollector

class ConnCollector(BaseCollector): 
    CONN_STATE_DESCRIPTIONS = {
        'S0': 'Stealth Scan Attempt (S0)', 'S1': 'Half Open Scan (S1)',
        'S2': 'Suspicious Connection (S2)', 'S3': 'No Response From Server (S3)',
        'REJ': 'Connection Rejected (REJ)', 'SF': 'Normal Connection (SF)',
        'RSTO': 'Reset by Originator (RSTO)', 'RSTR': 'Reset by Responder (RSTR)',
    }
    # HISTORY_PATTERNS = {
    #     "S": {"label": "SYN Scan or Silent Drop", "summary": "Only SYN sent, no response. Likely a stealth scan or silent drop.", "severity": "High"},
    #     "ShR": {"label": "Half-Open Scan (RST by Originator)", "summary": "Received SYN/ACK but originator sent RST. Classic half-open scan.", "severity": "High"},
    #     "SRA": {"label": "Immediate Rejection (RST by Responder)", "summary": "SYN sent, immediate RST from responder. Port likely closed or firewalled.", "severity": "High"},
    #     "ShADr": {"label": "Server Aborted After Data", "summary": "Full handshake, data exchange, then server issued RST. Possible IPS/IDS drop.", "severity": "High"},
    #     "ShA": {"label": "Handshake Only, No Data", "summary": "Handshake completed, but no data sent. May indicate probing.", "severity": "Medium"},
    # }
    # NORMAL_HISTORY = {"ShADadfF", "ShADadGfF", "SADadfF", "ShADaggdgF", "ShADagdgTFf","ShADagdgTfF"}
    
    @property
    def collector_name(self) -> str:
        return "conn"

    # def _interpret_history(self, history: str | None) -> Dict[str, str] | None:
    #         if not history:
    #             return None

    #         # --- PHÂN TÍCH THEO SỰ KIỆN (TOKEN-BASED) ---

    #         has_syn = 'S' in history
    #         has_syn_ack = 'h' in history
    #         has_ack = 'A' in history
    #         has_data_orig = 'D' in history
    #         has_data_resp = 'd' in history
    #         has_fin_orig = 'F' in history
    #         has_fin_resp = 'f' in history
    #         has_rst = 'R' in history or 'r' in history
    #         has_retransmission = 'T' in history

    #         handshake_complete = has_syn and has_syn_ack and has_ack
    #         data_exchanged = has_data_orig or has_data_resp
    #         graceful_close = has_fin_orig or has_fin_resp

    #         # --- XÂY DỰNG KẾT LUẬN DỰA TRÊN LOGIC ---

    #         # MỨC ĐỘ HIGH: Các hành vi quét mạng hoặc bị từ chối rõ ràng
    #         if has_syn and not has_syn_ack and not has_rst:
    #             return {"label": "Stealth Scan (SYN)", "summary": "Client sent SYN but received no response. Classic stealth scan.", "severity": "High"}
            
    #         if has_syn and has_syn_ack and 'r' in history and not has_ack:
    #             return {"label": "Half-Open Scan (RST by Originator)", "summary": "Client completed half the handshake then sent RST. Classic half-open scan.", "severity": "High"}

    #         if has_syn and 'R' in history and not has_syn_ack:
    #             return {"label": "Connection Rejected (RST by Responder)", "summary": "Server immediately rejected the connection with a RST packet. Port likely closed.", "severity": "High"}

    #         # MỨC ĐỘ MEDIUM: Kết nối đáng ngờ nhưng không rõ mục đích
    #         if handshake_complete and not data_exchanged and not has_rst:
    #             return {"label": "Probing (Handshake Only)", "summary": "A full TCP handshake was completed, but no data was exchanged. May indicate probing.", "severity": "Medium"}

    #         if handshake_complete and data_exchanged and has_rst:
    #             return {"label": "Connection Aborted", "summary": "Connection was established and data was exchanged, but it was terminated abruptly with a RST.", "severity": "Medium"}

    #         # MỨC ĐỘ INFORMATIONAL: Các kết nối trông có vẻ bình thường
    #         if handshake_complete and data_exchanged and graceful_close:
    #             summary_note = "A standard TCP session with handshake, data exchange, and graceful closure."
    #             if has_retransmission:
    #                 summary_note += " Note: Packet retransmissions were detected, indicating potential network instability."
    #                 return {"label": "Normal Connection (with Retransmissions)", "summary": summary_note, "severity": "Informational"}
    #             else:
    #                 return {"label": "Normal Full Connection", "summary": summary_note, "severity": "Informational"}

    #         # Trường hợp còn lại, không khớp các logic trên
    #         return {"label": "Complex/Unclassified Pattern", "summary": f"The connection history '{history}' does not match common patterns and requires manual review.", "severity": "Informational"}
    def _interpret_history(self, history: str | None) -> Dict[str, any] | None:
        if not history:
            return None

        # --- Bước 1: Thu thập các sự thật cơ bản từ chuỗi history ---
        attributes = set()
        
        # Sự kiện cơ bản
        if 'S' in history: attributes.add("SYN_SENT")
        if 'h' in history: attributes.add("SYN_ACK_RECEIVED")
        if 'A' in history: attributes.add("ACK_AFTER_SYN_ACK")
        if 'D' in history: attributes.add("DATA_SENT_BY_ORIGINATOR")
        if 'd' in history: attributes.add("DATA_SENT_BY_RESPONDER")
        if 'F' in history: attributes.add("FIN_SENT_BY_ORIGINATOR")
        if 'f' in history: attributes.add("FIN_SENT_BY_RESPONDER")
        if 'R' in history or 'r' in history: attributes.add("RST_DETECTED")
        if 'T' in history: attributes.add("RETRANSMISSIONS_DETECTED")

        # --- Bước 2: Suy luận các thuộc tính cấp cao hơn từ sự thật cơ bản ---
        handshake_complete = "SYN_SENT" in attributes and \
                             "SYN_ACK_RECEIVED" in attributes and \
                             "ACK_AFTER_SYN_ACK" in attributes
        
        if handshake_complete:
            attributes.add("HANDSHAKE_COMPLETE")
        else:
            attributes.add("NO_HANDSHAKE")

        if "DATA_SENT_BY_ORIGINATOR" in attributes or "DATA_SENT_BY_RESPONDER" in attributes:
            attributes.add("DATA_EXCHANGED")
        else:
            attributes.add("NO_DATA_EXCHANGED")

        if "FIN_SENT_BY_ORIGINATOR" in attributes or "FIN_SENT_BY_RESPONDER" in attributes:
            attributes.add("GRACEFUL_CLOSE_ATTEMPTED")
        
        # --- Bước 3: Xác định loại kết nối chính dựa trên các thuộc tính ---
        connection_type = "UNCLASSIFIED"

        if handshake_complete and "DATA_EXCHANGED" in attributes and "GRACEFUL_CLOSE_ATTEMPTED" in attributes:
            connection_type = "NORMAL"
        elif "SYN_SENT" in attributes and not "SYN_ACK_RECEIVED" in attributes:
            connection_type = "SCAN" # Bao gồm S0
        elif "SYN_SENT" in attributes and "SYN_ACK_RECEIVED" in attributes and "RST_DETECTED" in attributes and not "ACK_AFTER_SYN_ACK" in attributes:
            connection_type = "SCAN" # Bao gồm S1 (half-open)
        elif handshake_complete and "NO_DATA_EXCHANGED" in attributes:
            connection_type = "PROBE"
        elif "RST_DETECTED" in attributes:
            connection_type = "ABORTED"
        elif not handshake_complete:
            connection_type = "INCOMPLETE"
        
        return {
            "connection_type": connection_type,
            "attributes": sorted(list(attributes)), # Sắp xếp để output nhất quán
            "raw_history": history
        }
        
    def collect(self, log_lines: List[str]) -> Dict[str, Any] | None:
        if not log_lines: return None
        try:
            last_log_entry = json.loads(log_lines[-1])
        except (json.JSONDecodeError, IndexError):
            return None

        # --- PHẦN 1: IDENTITY ---
        source_ip = last_log_entry.get('id.orig_h')
        dest_ip = last_log_entry.get('id.resp_h')
        if last_log_entry.get('local_orig', False) and not last_log_entry.get('local_resp', False): direction = "Egress"
        elif not last_log_entry.get('local_orig', False) and last_log_entry.get('local_resp', False): direction = "Ingress"
        elif last_log_entry.get('local_orig', False) and last_log_entry.get('local_resp', False): direction = "Lateral"
        else: direction = "Unknown"
        
        identity = {
            "source_ip": f"{source_ip}",
            "source_port": f"{last_log_entry.get('id.orig_p')}",
            "destination_ip": f"{dest_ip}",
            "destination_port": f"{last_log_entry.get('id.resp_p')}",
            "traffic_direction": direction,
            "service": last_log_entry.get('service'),
            "transport_protocol": last_log_entry.get('proto'),
        }

        # --- PHẦN 2: PHÂN TÍCH VÀ THU THẬP BẰNG CHỨNG ---
        conn_state = last_log_entry.get('conn_state')
        history = last_log_entry.get('history')
        duration = last_log_entry.get('duration')
        orig_bytes = last_log_entry.get('orig_bytes', 0)
        resp_bytes = last_log_entry.get('resp_bytes', 0)
        
        # --- PHẦN 3: TÁI CẤU TRÚC OUTPUT THEO FORMAT CHUẨN ---
        analysis = {
            "connection_state": self.CONN_STATE_DESCRIPTIONS.get(conn_state, f"Unknown State ({conn_state})"),
            # "history_analysis": self._interpret_history(history),
        }

        statistics = {
             "duration_sec": round(duration, 4) if duration else 0.0,
             "sent_bytes": orig_bytes,
             "received_bytes": resp_bytes
        }

        # Phân tích traffic bất đối xứng và thêm vào analysis
        SIGNIFICANT_RATIO = 5 
        if orig_bytes > resp_bytes * SIGNIFICANT_RATIO and resp_bytes > 0:
            analysis["flow_analysis"] = {"direction": "upload", "ratio": round(orig_bytes / resp_bytes)}
        elif resp_bytes > orig_bytes * SIGNIFICANT_RATIO and orig_bytes > 0:
            analysis["flow_analysis"] = {"direction": "download", "ratio": round(resp_bytes / orig_bytes)}
        else:
            # Bổ sung trường hợp đối xứng
            analysis["flow_analysis"] = {"direction": "Symmetrical"}

        return {
            "identity": identity,
            "analysis": analysis,
            "statistics": statistics
        }