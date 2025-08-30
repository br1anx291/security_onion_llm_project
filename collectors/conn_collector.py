# FILE: collectors/conn_collector.py

import json
from ipaddress import ip_address
from typing import Any, Dict, List
from .base_collector import BaseCollector

class ConnCollector(BaseCollector):
    """Collects and summarizes Zeek `conn.log` data."""

    # Descriptions for Zeek's connection states.
    CONN_STATE_DESCRIPTIONS = {
        'S0': 'Connection attempt, no reply',
        'S1': 'Handshake started, closed by client before completion',
        'S2': 'Handshake started, closed by server before completion',
        'S3': 'Handshake started, no final ACK from client',
        'REJ': 'Connection rejected by server',
        'SF': 'Connection established and fully closed',
        'RSTO': 'Connection closed by client (RST)',
        'RSTR': 'Connection closed by server (RST)',
    }
    
    @property
    def collector_name(self) -> str:
        return "conn"

    def _is_private_ip(self, ip_str: str) -> bool:
        """Checks if a given string is a private IP address."""
        if not ip_str:
            return False
        try:
            return ip_address(ip_str).is_private
        except ValueError:
            return False

    def _get_traffic_direction(self, source_ip: str | None, dest_ip: str | None) -> str:
        """Determines traffic direction based on IP privacy."""
        is_source_private = self._is_private_ip(source_ip)
        is_dest_private = self._is_private_ip(dest_ip)

        if is_source_private and not is_dest_private: return "Egress"
        if not is_source_private and is_dest_private: return "Ingress"
        if is_source_private and is_dest_private: return "Lateral"
        return "Internet-to-Internet"

    def collect(self, log_lines: List[str]) -> Dict[str, Any] | None:
        """Processes the last conn log entry to summarize the connection."""
        if not log_lines:
            return None

        try:
            log = json.loads(log_lines[-1])
        except (json.JSONDecodeError, IndexError):
            return None
        
        # --- 1. Build Identity Conditionally ---
        identity = {}
        if source_ip := log.get('id.orig_h'): identity['source_ip'] = source_ip
        if source_port := log.get('id.orig_p'): identity['source_port'] = source_port
        if dest_ip := log.get('id.resp_h'): identity['destination_ip'] = dest_ip
        if dest_port := log.get('id.resp_p'): identity['destination_port'] = dest_port
        
        identity['traffic_direction'] = self._get_traffic_direction(log.get('id.orig_h'), log.get('id.resp_h'))
        
        if service := log.get('service'): identity['service'] = service
        if proto := log.get('proto'): identity['transport_protocol'] = proto

        # --- 2. Analysis ---
        conn_state = log.get('conn_state')
        assessment = "Informational: Standard connection recorded."
        if conn_state in ('S0', 'S1', 'S2', 'S3', 'REJ'):
            assessment = f"Suspicious: Connection failed with state '{conn_state}', which may indicate scanning."
        
        analysis = {
            "overall_assessment": assessment,
            "connection_state_desc": self.CONN_STATE_DESCRIPTIONS.get(conn_state, f"Unknown State ({conn_state})"),
            "flow_ratio": {
                "upload_bytes": log.get('orig_bytes', 0),
                "download_bytes": log.get('resp_bytes', 0),
                "ratio": round(log.get('orig_bytes', 0) / log.get('resp_bytes'), 1) if log.get('resp_bytes', 0) > 0 else "N/A"
            }
        }
        
        # --- 3. Statistics ---
        statistics = {
            "duration_seconds": round(log.get('duration', 0.0), 4)
        }

        # --- 4. Final Output ---
        final_output = {
            "analysis": analysis,
            "statistics": statistics
        }
        if identity:
            final_output["identity"] = identity
        
        return final_output