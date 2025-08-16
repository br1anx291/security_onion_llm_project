# FILE: collectors/files_collector.py

import json
import os
from typing import List, Dict, Any
from .base_collector import BaseCollector

class FilesCollector(BaseCollector):
    SUSPICIOUS_EXTENSIONS = {'.exe', '.dll', '.scr', '.bat', '.cmd', '.js', '.ps1', '.zip', '.rar', '.jar', '.bin'}
    SUSPICIOUS_MIME_TYPES = {'application/x-dosexec', 'application/x-msdownload', 'application/octet-stream', 'application/zip' , 'application/x-rar-compressed', 'application/vnd.ms-cab-compressed'}

    @property
    def collector_name(self) -> str:
        return "files"

    def collect(self, log_lines: List[str]) -> Dict[str, Any] | None:
        if not log_lines: return None
        
        # --- PHẦN 1: Thu thập và tổng hợp bằng chứng thô ---
        analyzed_files: List[Dict[str, Any]] = []
        suspicious_files_count = 0
        total_bytes_seen = 0
        
        # Thu thập các định danh chung cho cả phiên
        uids, source_ips, destination_ips, sources = set(), set(), set(), set()

        for line in log_lines:
            if not line: continue
            try:
                log_entry = json.loads(line)
                
                # --- A. Tổng hợp thông tin cấp cao ---
                uids.add(log_entry.get("uid"))
                source_ips.add(log_entry.get("id.orig_h"))
                destination_ips.add(log_entry.get("id.resp_h"))
                sources.add(log_entry.get("source"))
                total_bytes_seen += log_entry.get("seen_bytes", 0)

                # --- B. Phân tích chi tiết cho từng file ---
                
                # B.1. Identity của file
                file_identity = {"file_uid": log_entry.get("fuid")}
                if filename := log_entry.get('filename'): file_identity['filename'] = filename
                file_identity['file_type'] = log_entry.get('mime_type', 'unknown')
                hashes = {k: v for k, v in {'md5': log_entry.get('md5'), 'sha1': log_entry.get('sha1')}.items() if v}
                if hashes: file_identity['hashes'] = hashes
                file_identity['size'] = f"{round(log_entry.get('seen_bytes', 0) / 1024, 2)} KB"

                # B.2. Analysis của file
                notes = []
                if (mime_type := log_entry.get('mime_type')) and mime_type in self.SUSPICIOUS_MIME_TYPES:
                    notes.append(f"MIME: {mime_type}")
                if filename and os.path.splitext(filename)[1].lower() in self.SUSPICIOUS_EXTENSIONS:
                    notes.append(f"Extension: {os.path.splitext(filename)[1].lower()}")
                
                risk_assessment = f"Suspicious ({', '.join(notes)})" if notes else "Benign (Based on MIME/Extension)"
                if notes: suspicious_files_count += 1

                status_notes = []
                if log_entry.get('timedout', False): status_notes.append("Timed Out")
                if log_entry.get('missing_bytes', 0) > 0: status_notes.append("Missing Bytes")

                file_analysis = {
                    "risk_assessment": risk_assessment,
                    "transfer_direction": "Download" if not log_entry.get('is_orig', False) else "Upload",
                    "transfer_status": f"Incomplete ({', '.join(status_notes)})" if status_notes else "Complete"
                }

                analyzed_files.append({"identity": file_identity, "analysis": file_analysis})
            except (json.JSONDecodeError, KeyError): continue

        if not analyzed_files: return None
        
        # --- PHẦN 2: Xây dựng output cuối cùng theo cấu trúc chuẩn ---
        
        identity = {
            # "uid": list(uids)[0] if uids else None,
            # "source_ip": list(source_ips)[0] if source_ips else None,
            # "destination_ip": list(destination_ips)[0] if destination_ips else None,
            "source_protocol": list(sources)[0] if sources else None
        }

        analysis = {
            "session_risk": "Suspicious Files Detected" if suspicious_files_count > 0 else "No Suspicious Files Detected"
        }
        
        statistics = {
            "total_files_analyzed": len(analyzed_files),
            "suspicious_files_count": suspicious_files_count,
            "total_bytes_seen_kb": round(total_bytes_seen / 1024, 2)
        }
        
        evidence = {
            "analyzed_files_summary": analyzed_files
        }

        return {
            "identity": identity,
            "statistics": statistics,
            "analysis": analysis,
            "evidence": evidence
        }