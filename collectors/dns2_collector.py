# FILE: collectors/dns_collector_upgraded.py

import json
import math
from collections import Counter
from typing import List, Dict, Any

# Lớp BaseCollector giả định
class BaseCollector:
    def __init__(self, zeek_logs_dir: str = None):
        self.zeek_logs_dir = zeek_logs_dir
    @property
    def collector_name(self) -> str: raise NotImplementedError
    def collect(self, log_lines: List[str]) -> Dict[str, Any] | None: raise NotImplementedError

class DnsCollector(BaseCollector):
    
    # --- CÁC NGƯỠNG VÀ DANH SÁCH (có thể cấu hình) ---
    SUSPICIOUS_QTYPES = {'*', 'TXT', 'ANY', 'NBSTAT', 'NIMLOC'}
    FAILURE_RCODES = {'NXDOMAIN', 'SERVFAIL', 'REFUSED'}
    SUSPICIOUS_TLDS = {'.xyz', '.icu', '.net', '.org', '.cn','.tk', '.pw', '.sbs', '.club', '.top'}
    
    LOW_TTL_THRESHOLD = 60
    HIGH_ENTROPY_THRESHOLD = 3.0 # Tăng nhẹ ngưỡng để giảm false positive
    LONG_QUERY_THRESHOLD = 50
    MIN_QUERIES_FOR_STAT_SIGNIFICANCE = 10 # NÂNG CẤP 1: Ngưỡng để đánh giá tỷ lệ lỗi
    REPETITIVE_QUERY_THRESHOLD = 20
    
    @property
    def collector_name(self) -> str:
        return "dns"
    
    def _calculate_shannon_entropy(self, text: str) -> float:
        if not text: return 0.0
        # Bỏ qua các ký tự không phải chữ và số để tính toán chính xác hơn
        text = ''.join(filter(str.isalnum, text))
        if not text: return 0.0
        counts = Counter(text); text_len = len(text)
        return -sum((count / text_len) * math.log2(count / text_len) for count in counts.values())
    
    def collect(self, log_lines: List[str]) -> Dict[str, Any] | None:
        if not log_lines: return None
        
        # --- PHẦN 1: Thu thập bằng chứng thô ---
        distinct_queries, distinct_answers, found_suspicious_qtypes = set(), set(), set()
        total_queries, failed_queries_count = 0, 0
        min_ttl_found: int | None = None
        high_entropy_domains, suspicious_tld_domains, long_queries = [], [], []
        last_failure_rcode: str | None = None
        uid, source_ip, dns_server_ip = None, None, None
        query_counts = Counter()
        
        for line in log_lines:
            try:
                log_entry = json.loads(line)
                total_queries += 1
                
                if not uid: uid = log_entry.get("uid")
                if not source_ip: source_ip = log_entry.get("id.orig_h")
                if not dns_server_ip: dns_server_ip = log_entry.get("id.resp_h")

                if rcode := log_entry.get('rcode_name'):
                    if rcode in self.FAILURE_RCODES:
                        failed_queries_count += 1
                        last_failure_rcode = rcode
                
                if qtype := log_entry.get('qtype_name'):
                    if qtype in self.SUSPICIOUS_QTYPES: found_suspicious_qtypes.add(qtype)

                for ttl in log_entry.get('TTLs', []):
                    if ttl < self.LOW_TTL_THRESHOLD and (min_ttl_found is None or ttl < min_ttl_found):
                        min_ttl_found = int(ttl)

                if query := log_entry.get('query'):
                    distinct_queries.add(query)
                    if any(query.endswith(tld) for tld in self.SUSPICIOUS_TLDS): 
                        suspicious_tld_domains.append(query)
                    if len(query) > self.LONG_QUERY_THRESHOLD: 
                        long_queries.append(query)
                    
                    # ### NÂNG CẤP 2: Sửa lỗi tính entropy ###
                    # Phân tích các phần của tên miền thay vì chỉ `split('.')[0]`
                    if '.arpa' not in query:
                        parts = query.split('.')
                        # Chỉ phân tích entropy nếu có tên miền phụ (subdomain)
                        if len(parts) > 2:
                            # Lấy toàn bộ phần tên miền phụ, ví dụ: "a.b" trong "a.b.domain.com"
                            subdomain_part = '.'.join(parts[:-2])
                            if self._calculate_shannon_entropy(subdomain_part) > self.HIGH_ENTROPY_THRESHOLD:
                                high_entropy_domains.append(query)

                if answers := log_entry.get('answers'): distinct_answers.update(answers)
            except (json.JSONDecodeError, KeyError): continue

        if total_queries == 0: return None

        # --- PHẦN 2: Phân tích và tạo các tín hiệu ---
        query_risks = []
        if high_entropy_domains: query_risks.append("High Entropy Querys")
        if long_queries: query_risks.append("Long Querys")
        if suspicious_tld_domains: query_risks.append("Suspicious TLD")

        repetitive_queries_found = []
        for query, count in query_counts.items():
            if count >= self.REPETITIVE_QUERY_THRESHOLD:
                repetitive_queries_found.append({"query": query, "count": count})
        
        if repetitive_queries_found:
            query_risks.append("Repetitive Query Detected")
            
        failed_ratio = failed_queries_count / total_queries if total_queries > 0 else 0
        
        # ### NÂNG CẤP 3: Thêm ngữ cảnh cho trạng thái truy vấn ###
        query_status = "Success (NOERROR)"
        if failed_queries_count > 0:
            query_status = f"Failed ({last_failure_rcode})"
            # Chỉ cảnh báo tỷ lệ lỗi cao nếu số lượng truy vấn đủ lớn
            if total_queries >= self.MIN_QUERIES_FOR_STAT_SIGNIFICANCE and failed_ratio > 0.5:
                query_risks.append("High Failure Ratio")
            elif total_queries < self.MIN_QUERIES_FOR_STAT_SIGNIFICANCE:
                query_status += " (Low Query Count)"

        suspicious_qtype_analysis = f"Suspicious QTYPEs Found: {sorted(list(found_suspicious_qtypes))}" if found_suspicious_qtypes else "Normal QTYPEs"
        low_ttl_analysis = f"Low TTL Detected ({min_ttl_found}s)" if min_ttl_found is not None else "Normal TTLs"

        if not query_risks: query_risks.append("Normal Query Patterns")

        # --- PHẦN 3: Xây dựng output cuối cùng ---
        identity = {"source_ip": source_ip, "dns_server_ip": dns_server_ip}
        
        analysis = {
            "risks_identified": sorted(query_risks),
            "query_status_summary": query_status,
            "qtype_analysis": suspicious_qtype_analysis,
            "ttl_analysis": low_ttl_analysis
        }
        
        statistics = {
            "total_queries": total_queries,
            "distinct_queries": len(distinct_queries),
            "distinct_answers": len(distinct_answers),
            "failed_queries_ratio": round(failed_ratio, 2)
        }
        
        # ### NÂNG CẤP 4: Bằng chứng gọn gàng và đầy đủ hơn ###
        evidence = {}
        if distinct_queries: evidence["all_queries"] = sorted(list(distinct_queries))
        if distinct_answers: evidence["all_answers"] = sorted(list(distinct_answers))
        if high_entropy_domains: evidence["high_entropy_queries"] = high_entropy_domains
        if suspicious_tld_domains: evidence["suspicious_tld_queries"] = suspicious_tld_domains
        if long_queries: evidence["long_queries"] = long_queries
        if min_ttl_found is not None: evidence["lowest_ttl_found"] = min_ttl_found
        if repetitive_queries_found:
            evidence["repetitive_queries"] = repetitive_queries_found
            
        return {
            "identity": identity,
            "analysis": analysis,
            "statistics": statistics,
            "evidence": evidence
        }