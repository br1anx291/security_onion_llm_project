# FILE: collectors/files_collector.py

import json
import logging
from typing import List, Dict, Any, Tuple
from .base_collector import BaseCollector

class FilesCollector(BaseCollector):
    # --- CÁC HẰNG SỐ CẤU HÌNH ---
    SUSPICIOUS_EXTENSIONS = {'.exe', '.dll', '.scr', '.bat', '.cmd', '.js', '.ps1', '.zip', '.rar', '.jar', '.bin', '.vbs', '.hta', '.msi', '.docm', '.xlsm'}
    SUSPICIOUS_MIME_TYPES = {'application/x-dosexec', 'application/x-msdownload', 'application/octet-stream', 'application/zip' , 'application/x-rar-compressed', 'application/vnd.ms-cab-compressed'}
    HIGH_ENTROPY_THRESHOLD = 7.5

    # Cấu hình điểm rủi ro cho từng loại phát hiện
    RISK_SCORES = {
        "BASE": 5,
        "SUSPICIOUS_EXTENSION": 20,
        "SUSPICIOUS_MIME": 20,
        "HIGH_ENTROPY": 30,
        "MIME_MISMATCH": 40 # Đây là chỉ số mạnh cho thấy sự né tránh
    }

    @property
    def collector_name(self) -> str:
        return "files"

    def _calculate_risk(self, reasons: List[str]) -> Tuple[int, str]:
        """Tính toán điểm rủi ro và mức độ nghiêm trọng dựa trên các lý do."""
        score = self.RISK_SCORES["BASE"]
        for reason in reasons:
            score += self.RISK_SCORES.get(reason, 0)

        if score >= 90:
            severity = "Critical"
        elif score >= 70:
            severity = "High"
        elif score >= 40:
            severity = "Medium"
        else:
            severity = "Informational"
            
        return score, severity

    def collect(self, log_lines: List[str]) -> Dict[str, Any] | None:
        if not log_lines: return None

        # --- PHẦN 1: THU THẬP VÀ XỬ LÝ TỪNG LOG LINE ---
        
        findings = []
        total_bytes_seen = 0
        evasion_detected = False
        highest_severity = "Informational"
        severity_map = {"Informational": 0, "Medium": 1, "High": 2, "Critical": 3}

        for line in log_lines:
            if not line: continue
            try:
                log_entry = json.loads(line)
                
                # --- A. Phân tích và xây dựng Finding cho từng file ---
                reasons = []
                filename = log_entry.get('filename')
                
                # A.1. Kiểm tra các chỉ số đáng ngờ
                if filename and any(filename.lower().endswith(ext) for ext in self.SUSPICIOUS_EXTENSIONS):
                    reasons.append("SUSPICIOUS_EXTENSION")
                
                reported_mime = log_entry.get('mime_type')
                if reported_mime in self.SUSPICIOUS_MIME_TYPES:
                    reasons.append("SUSPICIOUS_MIME")

                if (entropy := log_entry.get('entropy')) and isinstance(entropy, (int, float)) and entropy > self.HIGH_ENTROPY_THRESHOLD:
                    reasons.append("HIGH_ENTROPY")
                    evasion_detected = True

                analysis_mime = log_entry.get('analysis_mime_type')
                if reported_mime and analysis_mime and reported_mime != analysis_mime:
                    reasons.append("MIME_MISMATCH")
                    evasion_detected = True

                # A.2. Tính toán rủi ro
                risk_score, severity = self._calculate_risk(reasons)
                if severity_map[severity] > severity_map[highest_severity]:
                    highest_severity = severity

                # A.3. Xây dựng đối tượng Finding
                file_finding = {
                    "type": "FileAnalysisFinding",
                    "fuid": log_entry.get("fuid"),
                    "filename": filename,
                    "direction": "Upload" if log_entry.get('is_orig', False) else "Download",
                    "severity": severity,
                    "risk_score": risk_score,
                    "size_bytes": log_entry.get("seen_bytes", 0),
                    "reasons": reasons
                }
                
                # Thêm các thông tin chi tiết nếu có
                if hashes := {k: v for k, v in {'md5': log_entry.get('md5'), 'sha1': log_entry.get('sha1')}.items() if v}:
                    file_finding['hashes'] = hashes
                if reported_mime: file_finding['file_type_reported'] = reported_mime
                if analysis_mime: file_finding['file_type_actual'] = analysis_mime
                if 'entropy' in log_entry: file_finding['entropy'] = round(log_entry['entropy'], 2)
                
                status_notes = []
                if log_entry.get('timedout', False): status_notes.append("Timed Out")
                if log_entry.get('missing_bytes', 0) > 0: status_notes.append("Missing Bytes")
                if status_notes:
                    file_finding['transfer_status'] = f"Incomplete ({', '.join(status_notes)})"
                
                findings.append(file_finding)
                total_bytes_seen += log_entry.get("seen_bytes", 0)

            except (json.JSONDecodeError, KeyError) as e:
                logging.warning(f"Skipping malformed or incomplete log line. Error: {e}. Line: {line.strip()}")
                continue
        
        if not findings: return None

        # --- PHẦN 2: TỔNG HỢP VÀ XÂY DỰNG OUTPUT CUỐI CÙNG ---
        
        suspicious_files_count = sum(1 for f in findings if f['severity'] not in ["Informational"])
        
        # 2.1. Xây dựng mục `analysis`
        analysis = {
            "session_risk_summary": "Suspicious file activity detected" if suspicious_files_count > 0 else "No suspicious file activity detected",
            "highest_threat_level": highest_severity,
            "evasion_techniques_detected": "Yes" if evasion_detected else "No",
            "suspicious_content_summary": f"{suspicious_files_count} file(s) flagged with Medium or higher severity." if suspicious_files_count > 0 else "No suspicious content identified."
        }

        # 2.2. Xây dựng mục `statistics`
        statistics = {
            "total_files_analyzed": len(findings),
            "suspicious_files_count": suspicious_files_count,
            "total_bytes_transferred_kb": round(total_bytes_seen / 1024, 2)
        }

        # 2.3. Xây dựng mục `evidence`
        evidence = {
            "findings": findings
        }

        return {
            "analysis": analysis,
            "statistics": statistics,
            "evidence": evidence
        }