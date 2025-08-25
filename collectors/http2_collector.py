import json
import re
import os
from typing import List, Dict, Any
from urllib.parse import unquote_plus

# Hàm giải mã đệ quy (giữ nguyên)
def decode_recursively(encoded_str: str) -> str:
    if not isinstance(encoded_str, str):
        return ""
    decoded_str = encoded_str
    while True:
        try:
            unquoted = unquote_plus(decoded_str)
            if unquoted == decoded_str:
                return unquoted.lower()
            decoded_str = unquoted
        except Exception:
            return decoded_str.lower()

# Lớp BaseCollector (giữ nguyên)
class BaseCollector:
    def __init__(self, zeek_logs_dir: str = None):
        self.zeek_logs_dir = zeek_logs_dir
    @property
    def collector_name(self) -> str:
        raise NotImplementedError
    def collect(self, log_lines: List[str]) -> Dict[str, Any] | None:
        raise NotImplementedError

### ===================================================================
### === BẮT ĐẦU PHIÊN BẢN HTTPCOLLECTOR ĐÃ VIẾT LẠI HOÀN TOÀN ===
### ===================================================================

class HttpCollector(BaseCollector):

    # Các hằng số (giữ nguyên từ phiên bản cải tiến trước)
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

    @property
    def collector_name(self) -> str:
        return "http"

    def _assess_file_risk(self, file_dict: Dict) -> str:
        """
        Hàm nội bộ để đánh giá rủi ro của một tập hợp file (upload hoặc download).
        Trả về 'Suspicious' hoặc 'Benign'.
        """
        all_filenames = {fn for details in file_dict.values() for fn in details["filenames"]}
        all_mimes = {mime for details in file_dict.values() for mime in details["mime_types"]}
        
        if any(os.path.splitext(fn)[1].lower() in self.SUSPICIOUS_EXTENSIONS for fn in all_filenames):
            return "Suspicious"
        if any(mime in self.SUSPICIOUS_MIME_TYPES for mime in all_mimes):
            return "Suspicious"
            
        return "Benign"

# <<< BẮT ĐẦU CODE MỚI CHO HÀM 'collect' >>>

    def collect(self, log_lines: List[str]) -> Dict[str, Any] | None:
        if not log_lines: return None

        # --- PHẦN 1: Thu thập và gom nhóm (Logic giữ nguyên như lần trước) ---
        total_requests, client_error_count = 0, 0
        total_req_body, total_resp_body = 0, 0
        uids, methods = set(), set()
        user_agent, direct_ip_host = None, None
        findings = []
        uploaded_files, downloaded_files = {}, {}
        grouped_content_findings = {}
        AGGREGATION_THRESHOLD = 3
        EXAMPLE_LIMIT = 3

        for line in log_lines:
            try:
                log_entry = json.loads(line)
                total_requests += 1
                if not user_agent and (ua := log_entry.get("user_agent")): user_agent = ua
                if not direct_ip_host and (host := log_entry.get("host", "")) and re.match(r"^\d{1,3}(\.\d{1,3}){3}(:\d+)?$", host):
                    direct_ip_host = host
                uids.add(log_entry.get("uid"))
                if method := log_entry.get("method"): methods.add(method)
                total_req_body += log_entry.get("request_body_len", 0)
                total_resp_body += log_entry.get("response_body_len", 0)
                content_to_analyze = {}
                if uri := log_entry.get("uri"): content_to_analyze['uri'] = uri
                if req_body := log_entry.get("request_body"): content_to_analyze['body'] = req_body
                for source, original_content in content_to_analyze.items():
                    decoded_content = decode_recursively(original_content)
                    if not decoded_content: continue
                    reasons = set()
                    if source == 'uri' and ('../' in decoded_content or '..\\' in decoded_content):
                        reasons.add("Potential Directory Traversal")
                    all_patterns = {**self.SENSITIVE_URI_PATTERNS, **self.SQLI_PATTERNS, **self.XSS_PATTERNS}
                    for reason, pattern in all_patterns.items():
                        if pattern.search(decoded_content):
                            reasons.add(reason)
                    if reasons:
                        reasons_key = tuple(sorted(list(reasons)))
                        if reasons_key not in grouped_content_findings:
                            grouped_content_findings[reasons_key] = {"count": 0, "examples": [], "sources": set()}
                        group = grouped_content_findings[reasons_key]
                        group["count"] += 1
                        group["sources"].add(source.upper())
                        if len(group["examples"]) < EXAMPLE_LIMIT:
                            group["examples"].append(original_content[:256])
                if orig_fuids := log_entry.get("orig_fuids"):
                    for i, fuid in enumerate(orig_fuids):
                        if fuid not in uploaded_files: uploaded_files[fuid] = {"filenames": set(), "mime_types": set()}
                        if (fns := log_entry.get("orig_filenames")) and i < len(fns): uploaded_files[fuid]["filenames"].add(fns[i])
                        if (mimes := log_entry.get("orig_mime_types")) and i < len(mimes): uploaded_files[fuid]["mime_types"].add(mimes[i])
                if resp_fuids := log_entry.get("resp_fuids"):
                    for i, fuid in enumerate(resp_fuids):
                        if fuid not in downloaded_files: downloaded_files[fuid] = {"filenames": set(), "mime_types": set()}
                        if (fns := log_entry.get("resp_filenames")) and i < len(fns): downloaded_files[fuid]["filenames"].add(fns[i])
                        if (mimes := log_entry.get("resp_mime_types")) and i < len(mimes): downloaded_files[fuid]["mime_types"].add(mimes[i])
                if 400 <= log_entry.get('status_code', 0) < 500: client_error_count += 1
            except (json.JSONDecodeError, KeyError): continue

        # --- PHẦN 2: Xử lý và tạo findings cuối cùng (Logic giữ nguyên) ---
        for reasons_key, group in grouped_content_findings.items():
            if group["count"] > AGGREGATION_THRESHOLD:
                findings.append({"type": "AggregatedContentFinding", "source": "/".join(sorted(list(group["sources"]))), "reasons": list(reasons_key), "count": group["count"], "examples": group["examples"]})
            else:
                for example in group["examples"]:
                    findings.append({"type": "Content Finding", "source": "/".join(sorted(list(group["sources"]))), "content": example, "reasons": list(reasons_key)})
        for fuid, details in uploaded_files.items():
            for filename in details.get("filenames", {"N/A"}):
                for mime_type in details.get("mime_types", {"N/A"}):
                    findings.append({"type": "File Finding", "direction": "upload", "fuid": fuid, "filename": filename, "mime_type": mime_type})
        for fuid, details in downloaded_files.items():
            for filename in details.get("filenames", {"N/A"}):
                for mime_type in details.get("mime_types", {"N/A"}):
                    findings.append({"type": "File Finding", "direction": "download", "fuid": fuid, "filename": filename, "mime_type": mime_type})

        # ===================================================================
        # === THAY ĐỔI 3: Nâng cấp logic xây dựng output cuối cùng ===
        # ===================================================================

        # 3.1. Xây dựng phần `analysis` đã được nâng cấp
        agent_category, _ = "Unknown", None
        if user_agent:
            ua_lower = user_agent.lower()
            if any((s in ua_lower) for s in self.ANOMALOUS_UA_SUBSTRINGS): agent_category = "Anomalous/Malformed"
            elif any((s in ua_lower) for s in self.SCRIPTING_AGENTS): agent_category = "Scripting/Tool"
            elif any((s in ua_lower) for s in self.OUTDATED_BROWSER_UA_SUBSTRINGS): agent_category = "Outdated Browser"
            else: agent_category = "Normal Browser"

        file_transfer_risk = "No File Transfer"
        if uploaded_files and downloaded_files:
            upload_risk = self._assess_file_risk(uploaded_files)
            download_risk = self._assess_file_risk(downloaded_files)
            file_transfer_risk = f"{upload_risk} Upload and {download_risk} Download Detected"
        elif uploaded_files:
            upload_risk = self._assess_file_risk(uploaded_files)
            file_transfer_risk = f"{upload_risk} Upload Detected"
        elif downloaded_files:
            download_risk = self._assess_file_risk(downloaded_files)
            file_transfer_risk = f"{download_risk} Download Detected"


        # --- SỬA LỖI CHẾT NGƯỜI & NÂNG CẤP GIÁ TRỊ ---
        # Sửa lỗi: kiểm tra cả hai loại finding
        has_content_risk = any(f['type'] in ['Content Finding', 'AggregatedContentFinding'] for f in findings)
        
        # Nâng cấp: Tạo `findings_summary`
        findings_summary = []
        for f in findings:
            if f['type'] == 'AggregatedContentFinding':
                reasons_str = f['reasons'][0] # Lấy lý do chính
                summary = f"Detected pattern '{reasons_str}' {f['count']} times in {f['source']}."
                findings_summary.append(summary)
            elif f['type'] == 'Content Finding':
                reasons_str = f['reasons'][0]
                summary = f"Detected pattern '{reasons_str}' in {f['source']}."
                findings_summary.append(summary)
        
        analysis = {
            "user_agent_category": agent_category,
            "destination_analysis": "Direct-to-IP Connection" if direct_ip_host else "Domain Name Connection",
            "content_risk": "Suspicious Content Detected" if has_content_risk else "No Suspicious Content",
            "file_transfer_risk": file_transfer_risk
        }
        # Chỉ thêm findings_summary nếu nó có nội dung
        if findings_summary:
            analysis['findings_summary'] = findings_summary

        # 3.2. Xây dựng phần `evidence` (giữ nguyên)
        # Phần này không đổi, bạn có thể copy từ code cũ
        _, agent_matched_keyword = "Unknown", None
        if user_agent and (kw := next((s for s in self.SCRIPTING_AGENTS if s in user_agent.lower()), None)):
            agent_matched_keyword = kw
        connection_context = {"methods_used": sorted(list(methods))}
        if user_agent: connection_context["user_agent_string"] = user_agent
        if agent_matched_keyword: connection_context["agent_matched_keyword"] = agent_matched_keyword
        if direct_ip_host: connection_context["destination_ip"] = direct_ip_host
        evidence = {
            "connection_context": connection_context,
            "findings": findings
        }

        # 3.3. Xây dựng phần `statistics` (giữ nguyên)
        statistics = {
            "total_requests": total_requests,
            "request_bytes": total_req_body,
            "response_bytes": total_resp_body,
            "client_error_ratio": round(client_error_count / total_requests, 2) if total_requests > 0 else 0,
        }
        
        return {
            "analysis": analysis, 
            "evidence": evidence,
            "statistics": statistics, 
        }

# <<< KẾT THÚC CODE MỚI CHO HÀM 'collect' >>>``
### ===================================================================
### === KẾT THÚC PHIÊN BẢN HTTPCOLLECTOR ĐÃ VIẾT LẠI HOÀN TOÀN ===
### ===================================================================