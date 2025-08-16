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
    HISTORY_PATTERNS = {
        "S": {"label": "SYN Scan or Silent Drop", "summary": "Only SYN sent, no response. Likely a stealth scan or silent drop.", "severity": "High"},
        "ShR": {"label": "Half-Open Scan (RST by Originator)", "summary": "Received SYN/ACK but originator sent RST. Classic half-open scan.", "severity": "High"},
        "SRA": {"label": "Immediate Rejection (RST by Responder)", "summary": "SYN sent, immediate RST from responder. Port likely closed or firewalled.", "severity": "High"},
        "ShADr": {"label": "Server Aborted After Data", "summary": "Full handshake, data exchange, then server issued RST. Possible IPS/IDS drop.", "severity": "High"},
        "ShA": {"label": "Handshake Only, No Data", "summary": "Handshake completed, but no data sent. May indicate probing.", "severity": "Medium"},
    }
    NORMAL_HISTORY = {"ShADadfF", "ShADadGfF", "SADadfF", "ShADaggdgF", "ShADagdgTFf","ShADagdgTfF"}
    
    @property
    def collector_name(self) -> str:
        return "conn"

    def _interpret_history(self, history: str | None) -> Dict[str, str] | None:
        if not history: return None 
        if history in self.HISTORY_PATTERNS: return self.HISTORY_PATTERNS[history]
        if history in self.NORMAL_HISTORY:
            return {"label": "Normal Full Connection", "summary": "A standard TCP session...", "severity": "Informational"}
        return {"label": "Unrecognized Pattern", "summary": f"Requires manual review: '{history}'.", "severity": "Informational"}

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
            "history_analysis": self._interpret_history(history),
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