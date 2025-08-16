# FILE: collectors/http_collector.py

import json
import logging
import re
from typing import List, Dict, Any

# Giả định BaseCollector tồn tại trong .base_collector
# from .base_collector import BaseCollector

# Để code chạy độc lập, ta tạo một lớp BaseCollector giả
class BaseCollector:
    def __init__(self, zeek_logs_dir: str = None):
        self.zeek_logs_dir = zeek_logs_dir
    
    @property
    def collector_name(self) -> str:
        raise NotImplementedError
        
    def collect(self, log_lines: List[str]) -> Dict[str, Any] | None:
        raise NotImplementedError

class HttpCollector(BaseCollector):
    
    ANOMALOUS_UA_SUBSTRINGS = {'svchost.exe'}
    SCRIPTING_AGENTS = {'python', 'java', 'curl', 'wget', 'powershell', 'go-http-client', 'bits'}
    OUTDATED_BROWSER_UA_SUBSTRINGS = {'msie 6', 'msie 7', 'msie 8', 'firefox/1', 'firefox/2', 'firefox/3', 'chrome/1', 'chrome/2', 'chrome/3'}
    SYSTEM_AGENTS = {'apt-http', 'windows-update-agent', 'apple-pubsub', 'microsoft ncsi'}

    SUSPICIOUS_URI_EXTENSIONS = {'.exe', '.dll', '.zip', '.rar', '.ps1', '.sh', '.php'}
    EXECUTABLE_MIME_TYPES = {
        'application/x-dosexec', 'application/x-msdownload', 'application/octet-stream',
        'application/zip', 'application/x-rar-compressed'
    }

    @property
    def collector_name(self) -> str:
        return "http"

    def collect(self, log_lines: List[str]) -> Dict[str, Any] | None:
        
        if not log_lines:
            return None

        # --- KHỞI TẠO CÁC BIẾN THEO DÕI ---
        total_requests = 0
        client_error_count = 0
        methods = set()
        
        # *** THÊM MỚI: Biến để lưu danh sách các request ***
        http_requests_summary = []

        direct_ip_connection = None
        downloaded_mime_types = []
        found_suspicious_uri = None
        agent_category = None
        user_agent_evidence = None

        for line in log_lines:
            if not line: continue
            try:
                log_entry = json.loads(line)
                total_requests += 1
                
                method = log_entry.get('method')
                host = log_entry.get('host', '')
                uri = log_entry.get('uri', '')
                user_agent = log_entry.get('user_agent', '')
                resp_mimes = log_entry.get('resp_mime_types', [])

                # *** THÊM MỚI: Tạo và lưu chuỗi request tóm tắt ***
                if method and host:
                    request_str = f"{method} {host}{uri}"
                    if request_str not in http_requests_summary:
                        http_requests_summary.append(request_str)
                
                # Logic phát hiện direct-to-ip
                if direct_ip_connection is None and re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?$", host):
                    direct_ip_connection = host

                # Logic phân tích User Agent
                if agent_category is None and user_agent:
                    user_agent_l = user_agent.lower()
                    ua_checks_map = {
                        'Anomalous/Malformed': self.ANOMALOUS_UA_SUBSTRINGS,
                        'Scripting/Tool': self.SCRIPTING_AGENTS,
                        'Outdated Browser': self.OUTDATED_BROWSER_UA_SUBSTRINGS,
                        'System Agent': self.SYSTEM_AGENTS
                    }
                    for category, substrings in ua_checks_map.items():
                        for sub in substrings:
                            if sub in user_agent_l:
                                agent_category = category
                                user_agent_evidence = sub
                                break 
                        if agent_category: break
                
                if agent_category is None and user_agent in ('', '-'):
                    agent_category = 'Empty'
                    user_agent_evidence = user_agent

                # Logic tìm URI đáng ngờ
                if found_suspicious_uri is None:
                    for ext in self.SUSPICIOUS_URI_EXTENSIONS:
                        if uri.lower().endswith(ext):
                            found_suspicious_uri = uri
                            break
                
                # Logic tìm MIME type thực thi
                for mime in resp_mimes:
                    if mime in self.EXECUTABLE_MIME_TYPES:
                        if mime not in downloaded_mime_types:
                            downloaded_mime_types.append(mime)
                            
                if method:
                    methods.add(method)
                
                if 400 <= log_entry.get('status_code', 0) < 500:
                    client_error_count += 1

            except (json.JSONDecodeError, KeyError):
                continue
        
        if total_requests == 0:
            return None

        client_error_ratio = (client_error_count / total_requests) if total_requests > 0 else 0.0

        output: Dict[str, Any] = {
            # *** THÊM MỚI: Thêm trường tóm tắt vào output ***
            "total_requests": total_requests,
            "methods": sorted(list(methods)),
            "http_requests": http_requests_summary,
            "client_error_ratio": round(client_error_ratio, 2)
        }
        if agent_category:
            output["user_agent_category"] = agent_category
        if user_agent_evidence:
            output["user_agent_evidence"] = user_agent_evidence
        if direct_ip_connection:
            output["direct_to_ip_connection"] = direct_ip_connection
        if downloaded_mime_types:
            output["downloaded_mime_types"] = downloaded_mime_types
        if found_suspicious_uri:
            output["suspicious_uri_found"] = found_suspicious_uri

        return output