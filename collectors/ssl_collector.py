# FILE: collectors/ssl_collector.py

import json
import logging
from typing import List, Dict, Any

import yaml
import tldextract
from .base_collector import BaseCollector

# Basic logging configuration
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class SslCollector(BaseCollector):
    """
    Analyzes Zeek ssl.log data for certificate issues, weak encryption,
    and threat intelligence matches (JA3/JA3S).
    """

    def __init__(self, zeek_logs_dir: str = None, config_path: str = './collectors/ssl_pattern.yaml'):
        super().__init__(zeek_logs_dir)
        try:
            with open(config_path, 'r') as f:
                self.config = yaml.safe_load(f)
        except (IOError, yaml.YAMLError) as e:
            logging.error(f"FATAL: Could not load configuration file '{config_path}': {e}")
            raise

    @property
    def collector_name(self) -> str:
        return "ssl"

    # --- Private Helper Methods ---

    def _get_sni_reputation(self, server_name: str) -> str:
        """Determines the reputation of a server name based on keywords and trusted lists."""
        # This helper function is already well-structured. No changes needed.
        if not server_name: return "Unknown"
        extracted = tldextract.extract(server_name)
        registered_domain = f"{extracted.domain}.{extracted.suffix}"
        
        reputation_config = self.config.get('reputation', {})
        if registered_domain in reputation_config.get('trusted_domains', {}):
            return reputation_config['trusted_domains'][registered_domain]
        
        domain_parts = set(server_name.lower().split('.')) | set(server_name.lower().split('-'))
        if not set(reputation_config.get('adware_keywords', [])).isdisjoint(domain_parts):
            return "Adware/Tracker"
        if not set(reputation_config.get('benign_keywords', [])).isdisjoint(domain_parts):
            return "Likely Benign Infrastructure"
            
        return "Unknown Reputation"

    def _process_log_entry(self, log: Dict, state: Dict):
        """Processes a single log entry and updates the session state."""
        state['uids'].add(log.get("uid"))
        if sn := log.get("server_name"): state['server_names'].add(sn)
        if j3 := log.get("ja3"): state['ja3_hashes'].add(j3)
        if j3s := log.get("ja3s"): state['ja3s_hashes'].add(j3s)
        if v := log.get("version"): state['versions'].add(v)
        if c := log.get("cipher"): state['ciphers'].add(c)
        if cfps := log.get("cert_chain_fps"): state['cert_chain_fps'].update(cfps)

        if log.get('established', False): state['handshake_established'] = True
        state['total_duration'] += log.get('duration', 0.0)

        # Check for weak security configurations
        security_config = self.config.get('security', {})
        if (v := log.get('version')) in security_config.get('weak_protocols', []):
            state['weak_protocols_found'].add(v)
        if (c := log.get('cipher')) in security_config.get('weak_ciphers', []):
            state['weak_ciphers_found'].add(c)
        
        # Check for certificate validation issues
        if status := log.get('validation_status', ''):
            status_lower = status.lower()
            if "self-signed" in status_lower: state['certificate_issues'].add("Self-Signed Certificate")
            if "unable to get local issuer" in status_lower: state['certificate_issues'].add("Untrusted Chain")
            if "has expired" in status_lower: state['certificate_issues'].add("Expired Certificate")

    def _build_analysis_section(self, state: Dict) -> Dict:
        """Builds the 'analysis' dictionary and the overall assessment."""
        # 1. Perform threat intel lookups
        threat_intel_config = self.config.get('threat_intel', {})
        ja3_matches = {h: threat_intel_config.get('known_malicious_ja3', {}).get(h) for h in state['ja3_hashes']}
        ja3s_matches = {h: threat_intel_config.get('known_malicious_ja3s', {}).get(h) for h in state['ja3s_hashes']}
        ja3_threat_name = next((name for name in ja3_matches.values() if name), None)
        ja3s_threat_name = next((name for name in ja3s_matches.values() if name), None)

        # 2. Build the overall assessment sentence
        assessment = "Benign: No significant threat indicators found."
        high_confidence_threats = []
        if ja3_threat_name: high_confidence_threats.append(f"a JA3 hash matching '{ja3_threat_name}'")
        if ja3s_threat_name: high_confidence_threats.append(f"a JA3S hash matching '{ja3s_threat_name}'")
        
        medium_confidence_anomalies = []
        if "Self-Signed Certificate" in state['certificate_issues']: medium_confidence_anomalies.append("a self-signed certificate")
        if "Untrusted Chain" in state['certificate_issues']: medium_confidence_anomalies.append("an untrusted certificate chain")

        if high_confidence_threats:
            assessment = f"High Confidence Threat: Session contains malware indicators, including {', '.join(high_confidence_threats)}."
        elif medium_confidence_anomalies:
            assessment = f"Suspicious: Session involves anomalies like {', '.join(medium_confidence_anomalies)}."
        elif state['weak_protocols_found'] or state['weak_ciphers_found']:
            assessment = "Informational: Session used weak encryption, indicating a policy violation."

        # 3. Construct the final analysis block (conditionally)
        analysis = {"overall_assessment": assessment}
        if state['certificate_issues']: analysis["observed_certificate_issues"] = sorted(list(state['certificate_issues']))
        if state['weak_protocols_found']: analysis["observed_weak_protocols"] = sorted(list(state['weak_protocols_found']))
        if state['weak_ciphers_found']: analysis["observed_weak_ciphers"] = sorted(list(state['weak_ciphers_found']))
        analysis["handshake_status"] = "Successful" if state['handshake_established'] else "Failed"
        
        return analysis

    # --- Main Collect Method ---
    def collect(self, log_lines: List[str]) -> Dict[str, Any] | None:
        """Orchestrates the collection and analysis of SSL/TLS log data."""
        if not log_lines:
            return None

        # 1. Initialize a state dictionary to hold all session data.
        state = {
            'uids': set(), 'ja3_hashes': set(), 'ja3s_hashes': set(), 'versions': set(), 'ciphers': set(),
            'server_names': set(), 'cert_chain_fps': set(), 'certificate_issues': set(),
            'weak_protocols_found': set(), 'weak_ciphers_found': set(),
            'total_duration': 0.0, 'handshake_established': False
        }

        # 2. Process each log entry to populate the state.
        for line in log_lines:
            try:
                log = json.loads(line)
                self._process_log_entry(log, state)
            except (json.JSONDecodeError, KeyError) as e:
                logging.warning(f"Error processing SSL log line: {e}. Skipping.")
                continue
        
        # Early exit if there's no meaningful data to analyze.
        if not state['server_names'] and not state['ja3_hashes']:
            return None

        # 3. Build the final report sections.
        analysis = self._build_analysis_section(state)
        
        # 4. Build evidence and statistics conditionally to ensure clean output.
        threat_intel_config = self.config.get('threat_intel', {})
        evidence = {}
        if state['server_names']: evidence["server_names"] = sorted(list(state['server_names']))
        if state['versions']: evidence["tls_versions_used"] = sorted(list(state['versions']))
        if state['ciphers']: evidence["ciphers_used"] = sorted(list(state['ciphers']))
        if state['cert_chain_fps']: evidence["certificate_chain_fingerprints"] = sorted(list(state['cert_chain_fps']))
        if state['ja3_hashes']:
            evidence["ja3_details"] = [
                {"hash": h, "threat_name": threat_intel_config.get('known_malicious_ja3', {}).get(h)}
                for h in sorted(list(state['ja3_hashes']))
            ]
        if state['ja3s_hashes']:
            evidence["ja3s_details"] = [
                {"hash": h, "threat_name": threat_intel_config.get('known_malicious_ja3s', {}).get(h)}
                for h in sorted(list(state['ja3s_hashes']))
            ]

        # 5. Assemble the final, clean output.
        final_output = {
            "analysis": analysis,
            "statistics": {"connection_duration_sec": round(state['total_duration'], 4)}
        }
        if evidence:
            final_output["evidence"] = evidence
        
        return final_output