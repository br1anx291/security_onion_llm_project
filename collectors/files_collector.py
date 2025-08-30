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

    def _build_final_output(self, findings: List, total_bytes: int) -> Dict:
        """Aggregates results and builds the final collector output dictionary."""
        suspicious_files = [f for f in findings if f['severity'] != "Informational"]
        suspicious_count = len(suspicious_files)
        
        # Determine highest severity and if evasion was detected
        highest_severity = "Informational"
        evasion_detected = False
        if suspicious_files:
            highest_severity = max(suspicious_files, key=lambda f: self.SEVERITY_LEVELS[f['severity']])['severity']
            if any("MIME_MISMATCH" in f['reasons'] or "HIGH_ENTROPY" in f['reasons'] for f in suspicious_files):
                evasion_detected = True

        # Build analysis section
        analysis = {
            "session_risk_summary": "Suspicious file activity detected" if suspicious_count > 0 else "No suspicious file activity detected",
            "highest_threat_level": highest_severity,
            "evasion_techniques_detected": evasion_detected,
            "suspicious_content_summary": f"{suspicious_count} file(s) flagged with Medium or higher severity."
        }
        
        # Build statistics section
        statistics = {
            "total_files_analyzed": len(findings),
            "suspicious_files_count": suspicious_count,
            "total_bytes_transferred_kb": round(total_bytes / 1024, 2)
        }

        return {
            "analysis": analysis,
            "statistics": statistics,
            "evidence": {"findings": findings}
        }

    # --- Main Collect Method ---
    def collect(self, log_lines: List[str]) -> Dict[str, Any] | None:
        """Orchestrates the analysis of a stream of file log entries."""
        if not log_lines:
            return None

        findings = []
        total_bytes_seen = 0

        for line in log_lines:
            try:
                log = json.loads(line)
                finding = self._process_log_entry(log)
                if finding:
                    findings.append(finding)
                    total_bytes_seen += finding.get("size_bytes", 0)
            except (json.JSONDecodeError, KeyError) as e:
                logging.warning(f"Skipping malformed file log line. Error: {e}")
                continue
        
        if not findings:
            return None

        return self._build_final_output(findings, total_bytes_seen)