# FILE: collectors/files_collector.py

import json
import logging
from typing import List, Dict, Any, Tuple
from .base_collector import BaseCollector

class FilesCollector(BaseCollector):
    """
    Analyzes Zeek files.log data, calculating a risk score for each file
    based on extension, MIME type, entropy, and potential evasion techniques.
    """
    # --- Configuration Constants ---
    SUSPICIOUS_EXTENSIONS = {'.exe', '.dll', '.scr', '.bat', '.cmd', '.js', '.ps1', '.zip', '.rar', '.jar', '.bin', '.vbs', '.hta', '.msi', '.docm', '.xlsm'}
    SUSPICIOUS_MIME_TYPES = {'application/x-dosexec', 'application/x-msdownload', 'application/octet-stream', 'application/zip' , 'application/x-rar-compressed', 'application/vnd.ms-cab-compressed'}
    HIGH_ENTROPY_THRESHOLD = 7.5

    # Risk scores for various indicators
    RISK_SCORES = {
        "BASE": 5,
        "SUSPICIOUS_EXTENSION": 20,
        "SUSPICIOUS_MIME": 20,
        "HIGH_ENTROPY": 30,
        "MIME_MISMATCH": 40  # Strong indicator of evasion
    }
    
    # Mapping severity to a numeric level for easy comparison
    SEVERITY_LEVELS = {"Informational": 0, "Medium": 1, "High": 2, "Critical": 3}

    @property
    def collector_name(self) -> str:
        return "files"

    # --- Private Helper Methods ---

    def _calculate_risk(self, reasons: List[str]) -> Tuple[int, str]:
        """Calculates a risk score and severity based on a list of reasons."""
        score = self.RISK_SCORES.get("BASE", 0)
        for reason in reasons:
            score += self.RISK_SCORES.get(reason, 0)

        if score >= 90: severity = "Critical"
        elif score >= 70: severity = "High"
        elif score >= 40: severity = "Medium"
        else: severity = "Informational"
            
        return score, severity

    def _process_log_entry(self, log: Dict) -> Dict | None:
        """Analyzes a single file log entry and constructs a finding dictionary."""
        reasons = []
        
        # 1. Check for suspicious indicators
        filename = log.get('filename')
        if filename and any(filename.lower().endswith(ext) for ext in self.SUSPICIOUS_EXTENSIONS):
            reasons.append("SUSPICIOUS_EXTENSION")
        
        reported_mime = log.get('mime_type')
        if reported_mime in self.SUSPICIOUS_MIME_TYPES:
            reasons.append("SUSPICIOUS_MIME")

        if (entropy := log.get('entropy')) and isinstance(entropy, (int, float)) and entropy > self.HIGH_ENTROPY_THRESHOLD:
            reasons.append("HIGH_ENTROPY")
            
        analysis_mime = log.get('analysis_mime_type')
        if reported_mime and analysis_mime and reported_mime != analysis_mime:
            reasons.append("MIME_MISMATCH")

        # 2. Calculate risk based on findings
        risk_score, severity = self._calculate_risk(reasons)

        # 3. Build the finding object, adding optional fields conditionally
        file_finding = {
            "type": "FileAnalysisFinding",
            "fuid": log.get("fuid"),
            "filename": filename,
            "direction": "Upload" if log.get('is_orig') else "Download",
            "severity": severity,
            "risk_score": risk_score,
            "size_bytes": log.get("seen_bytes", 0),
            "reasons": reasons
        }
        
        # Add optional details only if they exist
        if reported_mime: file_finding['file_type_reported'] = reported_mime
        if analysis_mime: file_finding['file_type_actual'] = analysis_mime
        if 'entropy' in log: file_finding['entropy'] = round(log['entropy'], 2)
        
        # Add hashes if present
        hashes = {k: v for k, v in {'md5': log.get('md5'), 'sha1': log.get('sha1')}.items() if v}
        if hashes: file_finding['hashes'] = hashes

        # Add transfer status notes if incomplete
        status_notes = []
        if log.get('timedout'): status_notes.append("Timed Out")
        if log.get('missing_bytes', 0) > 0: status_notes.append("Missing Bytes")
        if status_notes:
            file_finding['transfer_status'] = f"Incomplete ({', '.join(status_notes)})"
            
        return file_finding

    # --- Main Collect Method ---
    def collect(self, log_lines: List[str]) -> Dict[str, Any] | None:
        """Orchestrates the analysis and AGGREGATION of a stream of file log entries."""
        if not log_lines:
            return None

        # <<< THAY ĐỔI BẮT ĐẦU: Logic gom nhóm thay vì tạo danh sách phẳng >>>
        
        # Dictionary để gom nhóm các findings dựa trên lý do (reasons)
        grouped_findings: Dict[Tuple[str, ...], Dict] = {}
        total_bytes_seen = 0
        EXAMPLE_LIMIT = 5 # Giới hạn số lượng ví dụ filename cho mỗi nhóm

        for line in log_lines:
            try:
                log = json.loads(line)
                # Phân tích từng file để lấy ra finding ban đầu
                individual_finding = self._process_log_entry(log)
                
                if not individual_finding:
                    continue
                
                total_bytes_seen += individual_finding.get("size_bytes", 0)

                # Tạo một key duy nhất dựa trên các lý do phát hiện được
                reasons = tuple(sorted(individual_finding["reasons"]))
                if not reasons:
                    reasons = ("BENIGN",) # Nhóm các file lành tính lại với nhau

                # Nếu nhóm này chưa tồn tại, hãy khởi tạo nó
                if reasons not in grouped_findings:
                    grouped_findings[reasons] = {
                        "count": 0,
                        "total_size_bytes": 0,
                        "severities": [],
                        "risk_scores": [],
                        "example_filenames": set(),
                        "directions": set()
                    }

                # Cập nhật thông tin cho nhóm
                group = grouped_findings[reasons]
                group["count"] += 1
                group["total_size_bytes"] += individual_finding["size_bytes"]
                group["severities"].append(individual_finding["severity"])
                group["risk_scores"].append(individual_finding["risk_score"])
                group["directions"].add(individual_finding["direction"])
                
                # Chỉ thêm một vài ví dụ filename để output không bị dài
                if len(group["example_filenames"]) < EXAMPLE_LIMIT and individual_finding["filename"]:
                    group["example_filenames"].add(individual_finding["filename"])

            except (json.JSONDecodeError, KeyError) as e:
                logging.warning(f"Skipping malformed file log line. Error: {e}")
                continue
        
        if not grouped_findings:
            return None

        return self._build_aggregated_output(grouped_findings, total_bytes_seen)

    # <<< THAY ĐỔI LỚN: Viết lại hoàn toàn hàm build output để xử lý dữ liệu đã gom nhóm >>>
    def _build_aggregated_output(self, grouped_findings: Dict, total_bytes: int) -> Dict:
        """Aggregates results from grouped findings and builds the final collector output."""
        
        aggregated_findings = []
        highest_session_severity = "Informational"
        session_evasion_detected = False
        total_suspicious_files = 0

        for reasons, group_data in grouped_findings.items():
            if reasons == ("BENIGN",):
                continue

            group_highest_severity = max(group_data["severities"], key=lambda s: self.SEVERITY_LEVELS[s])
            
            # <<< CẢI TIẾN LOGIC FILENAME BẮT ĐẦU >>>
            
            # 1. Lọc ra tất cả các filename có giá trị (không phải None)
            valid_filenames = sorted([fn for fn in group_data["example_filenames"] if fn])
            
            # 2. Nếu sau khi lọc không còn filename nào, sử dụng một thông báo ngắn gọn
            if not valid_filenames:
                display_filenames = ["No valid filenames recorded"]
            else:
                display_filenames = valid_filenames

            # <<< CẢI TIẾN LOGIC FILENAME KẾT THÚC >>>

            agg_finding = {
                "type": "AggregatedFileFinding",
                "count": group_data["count"],
                "reasons": list(reasons),
                "severity": group_highest_severity,
                "avg_risk_score": round(sum(group_data["risk_scores"]) / group_data["count"]),
                "directions": sorted(list(group_data["directions"])),
                "total_size_bytes": group_data["total_size_bytes"],
                "example_filenames": display_filenames # Sử dụng danh sách đã được xử lý
            }
            aggregated_findings.append(agg_finding)

            total_suspicious_files += group_data["count"]
            if self.SEVERITY_LEVELS[group_highest_severity] > self.SEVERITY_LEVELS[highest_session_severity]:
                highest_session_severity = group_highest_severity
            if "MIME_MISMATCH" in reasons or "HIGH_ENTROPY" in reasons:
                session_evasion_detected = True

        # ... (Phần còn lại của hàm giữ nguyên) ...
        analysis = {
            "session_risk_summary": f"Suspicious file activity detected ({total_suspicious_files} files)" if total_suspicious_files > 0 else "No suspicious file activity detected",
            "highest_threat_level": highest_session_severity,
            "evasion_techniques_detected": session_evasion_detected
        }
        
        statistics = {
            "total_files_analyzed": sum(g['count'] for g in grouped_findings.values()),
            "suspicious_files_count": total_suspicious_files,
            "suspicious_groups_count": len(aggregated_findings),
            "total_bytes_transferred_kb": round(total_bytes / 1024, 2)
        }

        return {
            "analysis": analysis,
            "statistics": statistics,
            "evidence": {"findings": aggregated_findings}
        }