# FILE: collectors/http_collector.py

import subprocess
import json
import logging
import re # Sử dụng regular expression để kiểm tra IP
from .base_collector import BaseCollector
from log_helper import find_log_files

class HttpCollector(BaseCollector):
    
    # Danh sách các user-agent của các công cụ dòng lệnh hoặc thư viện
    NON_BROWSER_UA_SUBSTRINGS = {'curl', 'wget', 'python-requests', 'go-http-client', 'powershell'}
    # Danh sách các user-agent của trình duyệt cũ
    OUTDATED_BROWSER_UA_SUBSTRINGS = {'msie 6', 'msie 7', 'msie 8', 'chrome/4', 'firefox/3'}
    
    
    # Danh sách các đuôi file đáng ngờ trong URI
    SUSPICIOUS_URI_EXTENSIONS = {'.exe', '.dll', '.zip', '.rar', '.ps1', '.sh', '.php'}
    
    # Các MIME type của file thực thi/nén
    EXECUTABLE_MIME_TYPES = {
        'application/x-dosexec', 'application/x-msdownload', 'application/octet-stream',
        'application/zip', 'application/x-rar-compressed'
    }

    @property
    def collector_name(self) -> str:
        return "http"

    def collect(self, uid: str, alert_timestamp: float) -> dict | None:
        list_of_log_files = find_log_files(
            self.zeek_logs_dir, self.collector_name, alert_timestamp
        )
        if not list_of_log_files:
            return None

        all_matching_lines = []
        command = "grep"
        for log_file in list_of_log_files:
            try:
                result = subprocess.run(
                    [command, uid, log_file],
                    capture_output=True, text=True, check=False
                )
                if result.returncode <= 1 and result.stdout:
                    all_matching_lines.extend(result.stdout.strip().split('\n'))
            except (subprocess.CalledProcessError, FileNotFoundError):
                continue

        if not all_matching_lines:
            return None

        # --- KHỞI TẠO CÁC BIẾN THEO DÕI ---
        total_requests = 0
        client_error_count = 0
        methods = set()
        
        # Tín hiệu
        direct_to_ip = False
        suspicious_ua = False
        downloaded_executable = False
        suspicious_uri = False
        
        # --- VÒNG LẶP PHÂN TÍCH NHANH ---
        for line in all_matching_lines:
            if not line: continue
            try:
                log_entry = json.loads(line)
                if log_entry.get('uid') != uid:
                    continue

                total_requests += 1
                
                # --- TÍNH TOÁN CÁC TÍN HIỆU ---
                
                host = log_entry.get('host', '')
                user_agent = log_entry.get('user_agent', '').lower()
                uri = log_entry.get('uri', '')
                resp_mimes = log_entry.get('resp_mime_types', [])
                
                # Tín hiệu 1: Kết nối thẳng đến IP
                if not direct_to_ip and re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", host):
                    direct_to_ip = True

                # Tín hiệu 2: User Agent đáng ngờ
                if not suspicious_ua:
                    if any(sub in user_agent for sub in self.NON_BROWSER_UA_SUBSTRINGS) or \
                       any(sub in user_agent for sub in self.OUTDATED_BROWSER_UA_SUBSTRINGS):
                        suspicious_ua = True

                # Tín hiệu 3: URI đáng ngờ
                if not suspicious_uri and any(uri.lower().endswith(ext) for ext in self.SUSPICIOUS_URI_EXTENSIONS):
                    suspicious_uri = True
                
                # Tín hiệu 4: Tải file thực thi
                if not downloaded_executable:
                    if any(mime in self.EXECUTABLE_MIME_TYPES for mime in resp_mimes):
                        downloaded_executable = True

                # Thu thập các thông tin thống kê
                if log_entry.get('method'):
                    methods.add(log_entry['method'])
                
                if 400 <= log_entry.get('status_code', 0) < 500:
                    client_error_count += 1

            except (json.JSONDecodeError, KeyError):
                continue
        
        if total_requests == 0:
            return None

        # --- XÂY DỰNG BẢN TÓM TẮT SIÊU CÔ ĐỌNG ---
        client_error_ratio = (client_error_count / total_requests) if total_requests > 0 else 0.0

        return {
            "total_requests": total_requests,
            "methods": sorted(list(methods)),
            "client_error_ratio": round(client_error_ratio, 2),
            # "signals": {
            #     "direct_to_ip": direct_to_ip,
            #     "suspicious_ua": suspicious_ua,
            #     "downloaded_executable": downloaded_executable,
            #     "suspicious_uri": suspicious_uri
            # }
        }