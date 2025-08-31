# FILE: collectors/http_collector.py

import json
import re
import os
from typing import List, Dict, Any
from urllib.parse import unquote_plus
from .base_collector import BaseCollector

class HttpCollector(BaseCollector):
    """
    Collects and analyzes Zeek http.log data to identify suspicious
    patterns, file transfers, and potential web attacks.
    """
    # --- Constants for Analysis ---
    ANOMALOUS_UA_SUBSTRINGS = {'svchost.exe'}
    SCRIPTING_AGENTS = {'python', 'java', 'curl', 'wget', 'powershell', 'go-http-client', 'bits'}
    OUTDATED_BROWSER_UA_SUBSTRINGS = {'msie 6', 'msie 7', 'msie 8', 'firefox/1', 'firefox/2', 'firefox/3'}
    
    SUSPICIOUS_EXTENSIONS = {'.exe', '.dll', 'scr', '.bat', '.cmd', '.js', '.ps1', '.jar', '.bin', 'php'}
    SUSPICIOUS_MIME_TYPES = {
        'application/x-dosexec', 'application/x-msdownload', 'application/octet-stream',
        'application/zip', 'application/x-rar-compressed', 'application/vnd.ms-cab-compressed'
    }
    
    SENSITIVE_URI_PATTERNS = {
        "Sensitive Keyword": re.compile(r'password|passwd|pwd|token|secret|apikey|api_key|access_token|session|auth|credentials', re.IGNORECASE),
        "Hex-based Key": re.compile(r'([a-fA-F0-9]{32,})')
    }
    SQLI_PATTERNS = {
        "Classic SQLi": re.compile(r"(\s*')\s*(or|and)\s*(\s*\S+\s*=\s*\S+)|union\s+select|--|/\*|\*/", re.IGNORECASE),
        "Time-based Blind": re.compile(r"benchmark\s*\(|sleep\s*\(", re.IGNORECASE)
    }
    XSS_PATTERNS = {
        "Script Tag": re.compile(r"<script|javascript:", re.IGNORECASE),
        "HTML Event Handler": re.compile(r"onerror\s*=|onload\s*=|onmouseover\s*=", re.IGNORECASE),
        "Img/Svg Payload": re.compile(r"<img|<svg", re.IGNORECASE)
    }
    WEBSHELL_PATTERNS = {
        # Pattern này sẽ tìm các lệnh đáng ngờ là GIÁ TRỊ của một tham số bất kỳ
        "Web Shell Command in Parameter": re.compile(
            r'=\s*(whoami|uname|id|ls|cat\s|system\s*\(|exec\s*\(|passthru\s*\()', # <-- SỬA LẠI: Tìm các lệnh nằm SAU dấu bằng
            re.IGNORECASE
        ),
           # Pattern này sẽ tìm tên file có chứa các từ khóa đáng ngờ
        "Suspicious Script in Uploads": re.compile(
            r'/uploads?/.*(shell|c99|r57|webadmin|admin|root| backdoor)\.php', # <-- SỬA LẠI: Tìm file có chứa chữ 'shell', không cần chính xác
            re.IGNORECASE
        )
    }
    # Aggregation constants
    AGGREGATION_THRESHOLD = 3
    EXAMPLE_LIMIT = 3

    def __init__(self, zeek_logs_dir: str):
        super().__init__(zeek_logs_dir)
        # Pre-compile all patterns for efficiency.
        self.ALL_PATTERNS = {
            **self.SENSITIVE_URI_PATTERNS,
            **self.SQLI_PATTERNS,
            **self.XSS_PATTERNS,
            **self.WEBSHELL_PATTERNS 
        }

    @property
    def collector_name(self) -> str:
        return "http"

    # --- Private Helper Methods ---

    @staticmethod
    def _decode_recursively(encoded_str: str) -> str:
        """Recursively URL-decodes a string until it's stable."""
        if not isinstance(encoded_str, str):
            return ""
        decoded_str = encoded_str
        # Limit iterations to prevent infinite loops on malformed input.
        for _ in range(10):
            try:
                unquoted = unquote_plus(decoded_str)
                if unquoted == decoded_str:
                    return unquoted.lower()
                decoded_str = unquoted
            except Exception:
                return decoded_str.lower()
        return decoded_str.lower()

    def _assess_file_risk(self, file_dict: Dict) -> str:
        """Assesses risk of a file collection (uploads/downloads)."""
        all_filenames = {fn for details in file_dict.values() for fn in details.get("filenames", [])}
        all_mimes = {mime for details in file_dict.values() for mime in details.get("mime_types", [])}
        
        if any(os.path.splitext(fn)[1].lower() in self.SUSPICIOUS_EXTENSIONS for fn in all_filenames):
            return "Suspicious"
        if any(mime in self.SUSPICIOUS_MIME_TYPES for mime in all_mimes):
            return "Suspicious"
        return "Benign"

    def _analyze_content(self, log: Dict, grouped_findings: Dict):
        """Analyzes URI and request body for suspicious patterns."""
        content_to_analyze = {
            'uri': log.get("uri", ""),
            'body': log.get("request_body", "")
        }

        for source, original_content in content_to_analyze.items():
            if not original_content:
                continue
            
            decoded_content = self._decode_recursively(original_content)
            reasons = set()

            # Check for directory traversal separately as it's not a regex pattern
            if source == 'uri' and ('../' in decoded_content or '..\\' in decoded_content):
                reasons.add("Potential Directory Traversal")

            for reason, pattern in self.ALL_PATTERNS.items():
                if pattern.search(decoded_content):
                    reasons.add(reason)

            if reasons:
                reasons_key = tuple(sorted(list(reasons)))
                if reasons_key not in grouped_findings:
                    grouped_findings[reasons_key] = {"count": 0, "examples": [], "sources": set()}
                
                group = grouped_findings[reasons_key]
                group["count"] += 1
                group["sources"].add(source.upper())
                if len(group["examples"]) < self.EXAMPLE_LIMIT:
                    group["examples"].append(original_content[:256])

    def _extract_files(self, log: Dict, direction: str, file_container: Dict):
        """Helper to extract uploaded or downloaded file information."""
        prefix = "orig" if direction == "upload" else "resp"
        if fuids := log.get(f"{prefix}_fuids"):
            filenames = log.get(f"{prefix}_filenames", [])
            mime_types = log.get(f"{prefix}_mime_types", [])
            for i, fuid in enumerate(fuids):
                if fuid not in file_container:
                    file_container[fuid] = {"filenames": set(), "mime_types": set()}
                if i < len(filenames):
                    file_container[fuid]["filenames"].add(filenames[i])
                if i < len(mime_types):
                    file_container[fuid]["mime_types"].add(mime_types[i])

    def _build_final_findings(self, grouped_findings: Dict, uploaded_files: Dict, downloaded_files: Dict) -> List[Dict]:
        """Aggregates and formats all findings from the session, including aggregated file transfers."""
        findings = []
        # --- Bước 1: Xử lý content findings (giữ nguyên) ---
        for reasons_key, group in grouped_findings.items():
            common_data = {"source": "/".join(sorted(list(group["sources"]))), "reasons": list(reasons_key)}
            if group["count"] > self.AGGREGATION_THRESHOLD:
                findings.append({"type": "AggregatedContentFinding", "count": group["count"], "examples": group["examples"], **common_data})
            else:
                for example in group["examples"]:
                    findings.append({"type": "ContentFinding", "content": example, **common_data})
        
        # --- Bước 2: Xử lý file findings theo logic gom nhóm MỚI ---
        for direction, container in [("upload", uploaded_files), ("download", downloaded_files)]:
            if not container:
                continue

            # Thu thập tất cả filenames và mime_types từ TẤT CẢ các file trong nhóm
            all_filenames = {fn for details in container.values() for fn in details.get("filenames", []) if fn}
            all_mimes = {mime for details in container.values() for mime in details.get("mime_types", []) if mime}
            
            # Tạo một finding tổng hợp duy nhất cho hướng này (upload hoặc download)
            aggregated_finding = {
                "type": "AggregatedFileTransfer",
                "direction": direction,
                "count": len(container), # Đếm số file duy nhất (dựa trên fuid)
                "filenames": sorted(list(all_filenames))[:self.EXAMPLE_LIMIT] if all_filenames else ["No valid filenames recorded"],
                "mime_types": sorted(list(all_mimes))
            }
            findings.append(aggregated_finding)
            
        return findings

    def _build_analysis_section(self, user_agent: str, direct_ip_host: str, findings: List, uploaded_files: Dict, downloaded_files: Dict) -> Dict:
        """Builds the final 'analysis' dictionary with an overall assessment."""
        # 1. Gather objective observations
        ua_lower = user_agent.lower() if user_agent else ""
        observed_ua_properties = [prop for prop, substrings in {
            "Anomalous Pattern": self.ANOMALOUS_UA_SUBSTRINGS,
            "Scripting/Tool Signature": self.SCRIPTING_AGENTS,
            "Outdated Browser Signature": self.OUTDATED_BROWSER_UA_SUBSTRINGS
        }.items() if any(s in ua_lower for s in substrings)]

        content_reasons = {reason for f in findings if f['type'] in ['ContentFinding', 'AggregatedContentFinding'] for reason in f['reasons']}
        upload_risk = self._assess_file_risk(uploaded_files)
        download_risk = self._assess_file_risk(downloaded_files)

        # 2. Determine threat level and build assessment sentence
        high_confidence_threats = []
        if "Anomalous Pattern" in observed_ua_properties: high_confidence_threats.append("an anomalous user agent")
        if upload_risk == "Suspicious": high_confidence_threats.append("suspicious file uploads")
        if "Classic SQLi" in content_reasons or "Time-based Blind" in content_reasons: high_confidence_threats.append("SQL Injection patterns")
        if "Script Tag" in content_reasons or "HTML Event Handler" in content_reasons: high_confidence_threats.append("Cross-Site Scripting (XSS) patterns")
        
        medium_confidence_anomalies = []
        if download_risk == "Suspicious": medium_confidence_anomalies.append("suspicious file downloads")
        if direct_ip_host: medium_confidence_anomalies.append("a direct-to-IP connection")
        if "Scripting/Tool Signature" in observed_ua_properties: medium_confidence_anomalies.append("a scripting tool user agent")
        if "Potential Directory Traversal" in content_reasons: medium_confidence_anomalies.append("directory traversal attempts")
        
        assessment = "Benign: No significant threat indicators found."
        if high_confidence_threats:
            assessment = f"High Confidence Threat: Session contains indicators of {', '.join(high_confidence_threats)}."
        elif medium_confidence_anomalies:
            assessment = f"Suspicious Anomaly: Session involves {', '.join(medium_confidence_anomalies)}."

        # 3. Construct the final analysis block
        return {
            "overall_assessment": assessment,
            "observed_user_agent_properties": observed_ua_properties or ["Normal"],
            "observed_destination": f"Direct-to-IP ({direct_ip_host})" if direct_ip_host else "Domain Name",
            "observed_content_patterns": sorted(list(content_reasons)) or ["None"],
            "observed_file_transfers": {
                "uploads": f"{len(uploaded_files)} files ({upload_risk})" if uploaded_files else "None",
                "downloads": f"{len(downloaded_files)} files ({download_risk})" if downloaded_files else "None"
            }
        }

    # --- Main Collect Method ---

    def collect(self, log_lines: List[str]) -> Dict[str, Any] | None:
        """
        Orchestrates the collection and analysis of HTTP log data.
        """
        if not log_lines:
            return None

        # 1. Initialize containers for the session data.
        total_requests, client_error_count = 0, 0
        total_req_body, total_resp_body = 0, 0
        user_agent, direct_ip_host = None, ""
        methods = set()
        uploaded_files, downloaded_files = {}, {}
        grouped_content_findings = {}

        # 2. Process each log entry to populate containers.
        for line in log_lines:
            try:
                log = json.loads(line)
                total_requests += 1
                methods.add(log.get("method"))
                total_req_body += log.get("request_body_len", 0)
                total_resp_body += log.get("response_body_len", 0)
                if 400 <= log.get('status_code', 0) < 500: client_error_count += 1
                
                if not user_agent: user_agent = log.get("user_agent")
                if not direct_ip_host and (host := log.get("host", "")) and re.match(r"^\d{1,3}(\.\d{1,3}){3}(:\d+)?$", host):
                    direct_ip_host = host
                
                self._analyze_content(log, grouped_content_findings)
                self._extract_files(log, "upload", uploaded_files)
                self._extract_files(log, "download", downloaded_files)

            except (json.JSONDecodeError, KeyError):
                continue

        # 3. Build the final report sections from the collected data.
        final_findings = self._build_final_findings(grouped_content_findings, uploaded_files, downloaded_files)
        
        analysis = self._build_analysis_section(user_agent, direct_ip_host, final_findings, uploaded_files, downloaded_files)
        
        # --- MODIFICATION START: Build evidence conditionally for a cleaner output ---

        # Only add connection context keys if they have a value.
        connection_context = {
            "methods_used": sorted(list(methods))
        }
        if user_agent:
            connection_context["user_agent_string"] = user_agent
        
        # The main evidence dictionary.
        evidence = {
            "connection_context": connection_context
        }
        # Only add the findings key if the list is not empty.
        if final_findings:
            evidence["findings"] = final_findings

        # --- MODIFICATION END ---
        
        statistics = {
            "total_requests": total_requests,
            "request_bytes": total_req_body,
            "response_bytes": total_resp_body,
            "client_error_ratio": round(client_error_count / total_requests, 2) if total_requests > 0 else 0,
        }
        
        return {
            "analysis": analysis, 
            "evidence": evidence, # Use the new, conditionally-built evidence dict
            "statistics": statistics
        }