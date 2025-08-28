# FILE: collectors/dns_collector_final.py

import json
import math
from collections import Counter
from typing import List, Dict, Any
from .base_collector import BaseCollector
# Cần cài đặt: pip install tldextract
import tldextract

# Lớp BaseCollector giả định
# class BaseCollector:
#     def __init__(self, zeek_logs_dir: str = None):
#         self.zeek_logs_dir = zeek_logs_dir
#     @property
#     def collector_name(self) -> str: raise NotImplementedError
#     def collect(self, log_lines: List[str]) -> Dict[str, Any] | None: raise NotImplementedError

class DnsCollector(BaseCollector):
    
    # --- CÁC NGƯỠNG VÀ DANH SÁCH (CÓ THỂ CẤU HÌNH) ---
    SUSPICIOUS_QTYPES = {'*', 'TXT', 'ANY'}
    FAILURE_RCODES = {'NXDOMAIN', 'SERVFAIL', 'REFUSED'}
    SUSPICIOUS_TLDS = {'.xyz', '.icu', '.cn', '.tk', '.pw', '.sbs', '.club', '.top', '.ru', '.online'}
    
    LOW_TTL_THRESHOLD = 60
    HIGH_ENTROPY_THRESHOLD = 3.0
    LONG_QUERY_THRESHOLD = 50
    MIN_QUERIES_FOR_STAT_SIGNIFICANCE = 10
    REPETITIVE_QUERY_THRESHOLD = 20
    HIGH_FAILURE_RATIO_THRESHOLD = 0.5
    
    @property
    def collector_name(self) -> str:
        return "dns"
    
    def _calculate_shannon_entropy(self, text: str) -> float:
        if not text: return 0.0
        text = ''.join(filter(str.isalnum, text))
        if not text: return 0.0
        counts = Counter(text); text_len = len(text)
        return -sum((count / text_len) * math.log2(count / text_len) for count in counts.values())

    def collect(self, log_lines: List[str]) -> Dict[str, Any] | None:
        if not log_lines: return None

        # --- PHẦN 1: THU THẬP DỮ LIỆU THÔ VÀ TẠO "FINDINGS" ---
        
        # Biến lưu trữ chính cho các phát hiện
        findings: List[Dict[str, Any]] = []
        
        # Các biến thống kê và ngữ cảnh
        uid, source_ip, dns_server_ip = None, None, None
        total_queries, failed_queries_count = 0, 0
        distinct_queries, distinct_answers = set(), set()
        query_counts = Counter()
        last_failure_rcode: str | None = None
        
        # Cờ để đảm bảo một số loại finding chỉ được thêm một lần
        low_ttl_finding_added = False

        for line in log_lines:
            try:
                log_entry = json.loads(line)
                total_queries += 1

                # Lấy thông tin ngữ cảnh chung
                if not source_ip: source_ip = log_entry.get("id.orig_h")
                if not dns_server_ip: dns_server_ip = log_entry.get("id.resp_h")
                
                # Đếm các truy vấn thất bại
                if rcode := log_entry.get('rcode_name'):
                    if rcode in self.FAILURE_RCODES:
                        failed_queries_count += 1
                        last_failure_rcode = rcode
                
                # Xử lý các thông tin liên quan đến từng truy vấn
                if query := log_entry.get('query'):
                    distinct_queries.add(query)
                    query_counts[query] += 1

                    # Finding: TLD đáng ngờ
                    extracted_tld = tldextract.extract(query).suffix
                    if extracted_tld and f".{extracted_tld}" in self.SUSPICIOUS_TLDS:
                        findings.append({
                            "type": "AttributeFinding", "source": "query_tld",
                            "content": query, "reasons": [f"Suspicious TLD (.{extracted_tld})"]
                        })

                    # Finding: Truy vấn dài
                    if len(query) > self.LONG_QUERY_THRESHOLD:
                        findings.append({
                            "type": "AttributeFinding", "source": "query_length",
                            "content": query, "reasons": [f"Long Query ({len(query)} > {self.LONG_QUERY_THRESHOLD})"]
                        })
                    
                    # Finding: Entropy cao (DGA)
                    if '.arpa' not in query and (parts := query.split('.')) and len(parts) > 2:
                        subdomain_part = '.'.join(parts[:-2])
                        entropy_score = self._calculate_shannon_entropy(subdomain_part)
                        if entropy_score > self.HIGH_ENTROPY_THRESHOLD:
                            findings.append({
                                "type": "AttributeFinding", "source": "query_subdomain", "content": query,
                                "reasons": [f"High Shannon Entropy ({entropy_score:.2f} > {self.HIGH_ENTROPY_THRESHOLD})"]
                            })
                    
                    # Finding: Loại truy vấn đáng ngờ
                    if (qtype := log_entry.get('qtype_name')) and qtype in self.SUSPICIOUS_QTYPES:
                        findings.append({
                            "type": "AttributeFinding", "source": "query_type", "content": query,
                            "reasons": [f"Suspicious QTYPE ({qtype})"]
                        })

                # Finding: TTL thấp
                if not low_ttl_finding_added:
                    for ttl in log_entry.get('TTLs', []):
                        if ttl < self.LOW_TTL_THRESHOLD:
                            findings.append({
                                "type": "AttributeFinding", "source": "answer_record", "content": int(ttl),
                                "reasons": [f"Low TTL ({int(ttl)} < {self.LOW_TTL_THRESHOLD})"]
                            })
                            low_ttl_finding_added = True # Chỉ thêm finding này một lần
                            break
                
                # Thu thập các câu trả lời
                if answers := log_entry.get('answers'): distinct_answers.update(answers)

            except (json.JSONDecodeError, KeyError):
                continue
        
        # --- PHẦN 2: TẠO CÁC "FINDINGS" DỰA TRÊN PHÂN TÍCH TỔNG HỢP ---
        if not total_queries: return None

        # Finding: Truy vấn lặp lại
        for query, count in query_counts.items():
            if count >= self.REPETITIVE_QUERY_THRESHOLD:
                findings.append({
                    "type": "PatternFinding", "source": "query_stream", "content": query,
                    "reasons": [f"Repetitive Query ({count} >= {self.REPETITIVE_QUERY_THRESHOLD})"]
                })
        
        # Finding: Tỷ lệ lỗi cao
        failed_ratio = failed_queries_count / total_queries
        if total_queries >= self.MIN_QUERIES_FOR_STAT_SIGNIFICANCE and failed_ratio >= self.HIGH_FAILURE_RATIO_THRESHOLD:
            findings.append({
                "type": "PatternFinding", "source": "query_stream",
                "content": f"rcode_name: {last_failure_rcode}",
                "reasons": [f"High Failure Ratio ({failed_ratio:.0%} >= {self.HIGH_FAILURE_RATIO_THRESHOLD:.0%})"]
            })

        # --- PHẦN 3: XÂY DỰNG OUTPUT CUỐI CÙNG THEO FORMAT MỚI ---
        if not findings and failed_queries_count == 0:
    # Nếu không có finding nào và không có lỗi, đây là traffic sạch, không cần output
            return None

        # --- BẮT ĐẦU THAY ĐỔI LOGIC XÂY DỰNG ANALYSIS ---

        # 1. Khởi tạo các quan sát khách quan
        observed_attrs = {
            "pattern": "Normal",
            "integrity": f"Normal ({failed_queries_count / total_queries:.0%} failure rate)",
            "tld_risk": "Normal",
            "ttl_behavior": "Normal"
        }

        # 2. Ghi nhận các cờ tín hiệu từ findings
        has_dga = any('Entropy' in f['reasons'][0] for f in findings if f['type'] == 'AttributeFinding')
        has_repetitive = any('Repetitive' in f['reasons'][0] for f in findings if f['type'] == 'PatternFinding')
        has_high_failure = any('Failure' in f['reasons'][0] for f in findings if f['type'] == 'PatternFinding')
        has_suspicious_tld = any('TLD' in f['reasons'][0] for f in findings if f['type'] == 'AttributeFinding')
        low_ttl_finding = next((f for f in findings if 'TTL' in f['reasons'][0]), None)

        # 3. Cập nhật các quan sát dựa trên cờ
        if has_dga: observed_attrs['pattern'] = "High Entropy (DGA-like)"
        elif has_repetitive: observed_attrs['pattern'] = "Repetitive (Beaconing-like)"

        if has_suspicious_tld: observed_attrs['tld_risk'] = "Contains Monitored TLDs"
        if low_ttl_finding: observed_attrs['ttl_behavior'] = f"Low (Value: {low_ttl_finding['content']}s)"

        # 4. Xây dựng câu đánh giá tổng thể (overall_assessment)
        assessment = "Likely Benign: No significant threat indicators found."
        high_confidence_indicators = has_dga or has_high_failure or has_repetitive

        if high_confidence_indicators:
            reasons = []
            if has_dga: reasons.append("DGA-like patterns")
            if has_high_failure: reasons.append("a high failure rate")
            if has_repetitive: reasons.append("repetitive beaconing")
            assessment = f"Potential Threat: Activity exhibits suspicious patterns, including {', '.join(reasons)}."
        elif low_ttl_finding or has_suspicious_tld:
            assessment = "Benign Anomaly Likely: Low-confidence anomalies were observed (e.g., low TTL or monitored TLDs), but no strong threat patterns were detected."

        # 5. Tạo khối analysis cuối cùng
        analysis_summary = {
            "overall_assessment": assessment,
            "observed_query_pattern": observed_attrs['pattern'],
            "observed_integrity": observed_attrs['integrity'],
            "observed_tld_risk": observed_attrs['tld_risk'],
            "observed_ttl_behavior": observed_attrs['ttl_behavior']
        }

        # --- KẾT THÚC THAY ĐỔI LOGIC XÂY DỰNG ANALYSIS ---

        # Xây dựng cấu trúc JSON cuối cùng (giữ nguyên phần còn lại)
        return {
            "analysis": analysis_summary,
            "evidence": {
                "connection_context": {
                    "source_ip": source_ip,
                    "destination_dns_server": dns_server_ip
                },
                "findings": findings
            },
            "statistics": {
                "total_queries": total_queries,
                "distinct_queries": len(distinct_queries),
                "failed_queries_ratio": round(failed_ratio, 2),
                "distinct_answers": len(distinct_answers)
            }
        }