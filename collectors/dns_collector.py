# FILE: collectors/dns_collector.py

import json
import math
from collections import Counter
from typing import List, Dict, Any
from .base_collector import BaseCollector
# Required: pip install tldextract
import tldextract

class DnsCollector(BaseCollector):
    """Analyzes Zeek dns.log data for suspicious indicators like DGA,
    beaconing, and unusual query types."""

    # --- Analysis Thresholds and Constants ---
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

    # --- Private Helper Methods ---

    @staticmethod
    def _calculate_shannon_entropy(text: str) -> float:
        """Calculates the Shannon entropy of the alphanumeric parts of a string."""
        if not text: return 0.0
        text = ''.join(filter(str.isalnum, text))
        if not text: return 0.0
        
        counts = Counter(text)
        text_len = float(len(text))
        return -sum(count / text_len * math.log2(count / text_len) for count in counts.values())

    def _create_finding(self, f_type: str, source: str, content: Any, reason: str) -> Dict:
        """Standardizes the creation of finding dictionaries."""
        return {"type": f_type, "source": source, "content": str(content), "reasons": [reason]}

    def _process_log_entry(self, log: Dict, state: Dict):
        """Processes a single log entry, updating state and findings."""
        # --- Query-based analysis ---
        if query := log.get('query'):
            state["distinct_queries"].add(query)
            state["query_counts"][query] += 1

            # Check for suspicious Top-Level Domain (TLD)
            extracted = tldextract.extract(query)
            if f".{extracted.suffix}" in self.SUSPICIOUS_TLDS:
                state["findings"].append(self._create_finding(
                    "AttributeFinding", "query_tld", query, f"Suspicious TLD (.{extracted.suffix})"))
                state["anomalies"].add("suspicious_tld")

            # Check for overly long queries
            if len(query) > self.LONG_QUERY_THRESHOLD:
                state["findings"].append(self._create_finding(
                    "AttributeFinding", "query_length", query, f"Long Query ({len(query)} > {self.LONG_QUERY_THRESHOLD})"))
            
            # Check for high entropy in subdomains (potential DGA)
            subdomain = extracted.subdomain
            if subdomain:
                entropy = self._calculate_shannon_entropy(subdomain)
                if entropy > self.HIGH_ENTROPY_THRESHOLD:
                    state["findings"].append(self._create_finding(
                        "AttributeFinding", "query_subdomain", query, f"High Shannon Entropy ({entropy:.2f})"))
                    state["anomalies"].add("dga")
            
            # Check for suspicious query types (QTYPE)
            if (qtype := log.get('qtype_name')) in self.SUSPICIOUS_QTYPES:
                state["findings"].append(self._create_finding(
                    "AttributeFinding", "query_type", query, f"Suspicious QTYPE ({qtype})"))

        # --- Answer-based analysis ---
        if "low_ttl" not in state["anomalies"]:
            for ttl in log.get('TTLs', []):
                if ttl < self.LOW_TTL_THRESHOLD:
                    state["findings"].append(self._create_finding(
                        "AttributeFinding", "answer_record", int(ttl), f"Low TTL ({int(ttl)}s)"))
                    state["anomalies"].add("low_ttl")
                    state["low_ttl_value"] = int(ttl)
                    break # Only need one low TTL finding per session

    def _generate_session_findings(self, state: Dict):
        """Generates findings based on analysis of the entire session."""
        # Check for repetitive queries (potential beaconing)
        for query, count in state["query_counts"].items():
            if count >= self.REPETITIVE_QUERY_THRESHOLD:
                state["findings"].append(self._create_finding(
                    "PatternFinding", "query_stream", query, f"Repetitive Query ({count} times)"))
                state["anomalies"].add("repetitive")
        
        # Check for a high ratio of failed queries
        failure_ratio = state["failed_queries"] / state["total_queries"]
        if state["total_queries"] >= self.MIN_QUERIES_FOR_STAT_SIGNIFICANCE and failure_ratio >= self.HIGH_FAILURE_RATIO_THRESHOLD:
            state["findings"].append(self._create_finding(
                "PatternFinding", "query_stream", f"rcode_name: {state['last_failure_rcode']}", f"High Failure Ratio ({failure_ratio:.0%})"))
            state["anomalies"].add("high_failure")

    def _build_analysis_section(self, state: Dict) -> Dict:
        """Builds the final 'analysis' dictionary and overall assessment."""
        anomalies = state["anomalies"]
        
        # Determine overall patterns and risks
        pattern = "Normal"
        if "dga" in anomalies: pattern = "High Entropy (DGA-like)"
        elif "repetitive" in anomalies: pattern = "Repetitive (Beaconing-like)"
        
        tld_risk = "Suspicious" if "suspicious_tld" in anomalies else "Normal"
        ttl_behavior = f"Low ({state.get('low_ttl_value')}s)" if "low_ttl" in anomalies else "Normal"
        failure_rate = state["failed_queries"] / state["total_queries"]
        integrity = f"Normal ({failure_rate:.0%} failure rate)"

        # Build the final assessment sentence
        assessment = "Benign: No significant threat indicators found."
        high_confidence_reasons = []
        if "dga" in anomalies: high_confidence_reasons.append("DGA-like queries")
        if "high_failure" in anomalies: high_confidence_reasons.append("a high failure rate")
        if "repetitive" in anomalies: high_confidence_reasons.append("repetitive beaconing")

        if high_confidence_reasons:
            assessment = f"Potential Threat: Activity exhibits {', '.join(high_confidence_reasons)}."
        elif "low_ttl" in anomalies or "suspicious_tld" in anomalies:
            assessment = "Suspicious: Low-confidence anomalies observed (e.g., low TTL, monitored TLDs)."

        return {
            "overall_assessment": assessment,
            "observed_query_pattern": pattern,
            "observed_integrity": integrity,
            "observed_tld_risk": tld_risk,
            "observed_ttl_behavior": ttl_behavior
        }

    # --- Main Collect Method ---

    def collect(self, log_lines: List[str]) -> Dict[str, Any] | None:
        """Orchestrates the collection and analysis of DNS log data."""
        if not log_lines:
            return None

        # 1. Initialize a state dictionary to hold all session data.
        state = {
            "findings": [], "anomalies": set(), "query_counts": Counter(),
            "total_queries": 0, "failed_queries": 0, "last_failure_rcode": None,
            "distinct_queries": set(), "distinct_answers": set(),
            "source_ip": None, "dns_server_ip": None
        }

        # 2. Process each log entry to populate the state.
        for line in log_lines:
            try:
                log = json.loads(line)
                state["total_queries"] += 1
                
                # Capture context
                if not state["source_ip"]: state["source_ip"] = log.get("id.orig_h")
                if not state["dns_server_ip"]: state["dns_server_ip"] = log.get("id.resp_h")

                # Count failures
                if (rcode := log.get('rcode_name')) in self.FAILURE_RCODES:
                    state["failed_queries"] += 1
                    state["last_failure_rcode"] = rcode
                
                # Collect answers
                if answers := log.get('answers'): state["distinct_answers"].update(answers)

                # Process the log for specific attribute findings
                self._process_log_entry(log, state)

            except (json.JSONDecodeError, KeyError):
                continue
        
        if state["total_queries"] == 0:
            return None

        # 3. Generate findings based on the entire session's activity.
        self._generate_session_findings(state)

        # 4. If no anomalies found, no need to report.
        if not state["anomalies"]:
            return None

        # 5. Build the final report sections.
        analysis = self._build_analysis_section(state)
        
        
        
        # --- MODIFICATION START: Build evidence conditionally ---

        # Only add connection context keys if they have a value.
        connection_context = {}
        if state["source_ip"]:
            connection_context["source_ip"] = state["source_ip"]
        if state["dns_server_ip"]:
            connection_context["destination_dns_server"] = state["dns_server_ip"]
            
        # The main evidence dictionary.
        evidence = {}
        if connection_context:
            evidence["connection_context"] = connection_context
        # Only add the findings key if the list is not empty.
        if state["findings"]:
            evidence["findings"] = state["findings"]

        # --- MODIFICATION END ---

        return {
            "analysis": analysis,
            "evidence": evidence, # Use the new, conditionally-built evidence dict
            "statistics": {
                "total_queries": state["total_queries"],
                "distinct_queries": len(state["distinct_queries"]),
                "failed_queries_ratio": round(state["failed_queries"] / state["total_queries"], 2),
                "distinct_answers": len(state["distinct_answers"])
            }
        }