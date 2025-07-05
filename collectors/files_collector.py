# security_onion_llm_project/collectors/files_collector.py

import subprocess
import json
from typing import List, Dict, Any
from .base_collector import BaseCollector
from log_helper import find_log_files

class FilesCollector(BaseCollector):
    # --- Phần hằng số giữ nguyên ---
    SUSPICIOUS_MIME_TYPES = {
        'application/x-dosexec', 'application/x-msdownload', 'application/octet-stream',
        'application/zip', 'application/x-rar-compressed', 'application/java-archive',
        'application/pdf', 'application/msword', 'application/vnd.ms-excel',
        'application/vnd.ms-cab-compressed', 'application/x-shockwave-flash' # Đã có sẵn
    } 
    SUSPICIOUS_EXTENSIONS = {
        '.exe', '.dll', '.scr', '.pif', '.com', '.bat', '.cmd', '.vbs', '.vbe',
        '.js', '.jse', '.ps1', '.psm1', '.zip', '.rar', '.7z', '.jar',
        '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.bin' 
    }

    @property
    def collector_name(self) -> str:
        return "files"

    def collect(self, uid: str, alert_timestamp: float) -> Dict[str, Any] | None:
        # --- Phần tìm file log giữ nguyên ---
        list_of_log_files = find_log_files(
            self.zeek_logs_dir, self.collector_name, alert_timestamp
        )
        if not list_of_log_files:
            return None

        all_matching_lines: List[str] = []
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
        
        total_files_seen = 0
        suspicious_files_summary: List[Dict[str, Any]] = []
        
        for line in all_matching_lines:
            if not line: continue
            try:
                log_entry = json.loads(line)
                
                # === BẮT ĐẦU THAY ĐỔI QUAN TRỌNG ===
                # Logic kiểm tra UID linh hoạt hơn
                
                # Lấy danh sách các UID kết nối từ trường 'conn_uids'
                conn_uids_in_log = log_entry.get('conn_uids', [])
                
                # Nếu 'conn_uids' rỗng, hãy thử lấy từ trường 'uid' (dành cho các trường hợp khác)
                if not conn_uids_in_log and 'uid' in log_entry:
                    conn_uids_in_log.append(log_entry['uid'])
                
                # Nếu UID của chúng ta không nằm trong danh sách các UID liên quan, bỏ qua
                if uid not in conn_uids_in_log:
                    continue
                # === KẾT THÚC THAY ĐỔI QUAN TRỌNG ===

                total_files_seen += 1
                
                # --- Phần logic sàng lọc và tóm tắt giữ nguyên như cũ ---
                is_suspicious = False
                analysis_notes = []

                mime_type = log_entry.get('mime_type')
                if mime_type in self.SUSPICIOUS_MIME_TYPES:
                    is_suspicious = True

                filename = log_entry.get('filename')
                if filename:
                    file_ext = '.' + filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
                    if file_ext in self.SUSPICIOUS_EXTENSIONS:
                        is_suspicious = True
                
                if log_entry.get('timedout', False):
                    is_suspicious = True; analysis_notes.append("Analysis Timed Out")
                
                if log_entry.get('missing_bytes', 0) > 0:
                    is_suspicious = True; analysis_notes.append(f"Incomplete Transfer ({log_entry['missing_bytes']} bytes missing)")

                if is_suspicious:
                    size_in_bytes = log_entry.get('total_bytes') or log_entry.get('seen_bytes') or log_entry.get('missing_bytes', 0)
                    summary = {
                        "filename": filename,
                        "source_protocol": log_entry.get('source'),
                        "direction": "upload" if log_entry.get('is_orig') else "download",
                        "mime_type": mime_type,
                        "size_kb": round(size_in_bytes / 1024, 2) if size_in_bytes > 0 else 0.0,
                        "hashes": {
                            "md5": log_entry.get('md5'),
                            "sha1": log_entry.get('sha1'),
                            "sha256": log_entry.get('sha256')
                        },
                        "analysis_notes": analysis_notes
                    }
                    summary['hashes'] = {k: v for k, v in summary['hashes'].items() if v}
                    suspicious_files_summary.append(summary)

            except (json.JSONDecodeError, KeyError):
                continue

        if not suspicious_files_summary:
            return None
        
        return {
            "total_files_seen": total_files_seen,
            "suspicious_files_found": len(suspicious_files_summary),
            "suspicious_files_summary": suspicious_files_summary
        }