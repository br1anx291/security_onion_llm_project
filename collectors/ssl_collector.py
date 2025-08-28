import json
import logging
from typing import List, Dict, Any, Set

import yaml
import tldextract

# Cấu hình logging cơ bản
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Giả định BaseCollector tồn tại
class BaseCollector:
    def __init__(self, zeek_logs_dir: str = None):
        self.zeek_logs_dir = zeek_logs_dir
    @property
    def collector_name(self) -> str:
        raise NotImplementedError
    def collect(self, log_lines: List[str]) -> Dict[str, Any] | None:
        raise NotImplementedError

class SslCollector(BaseCollector):
    
    def __init__(self, zeek_logs_dir: str = None, config_path: str = './collectors/ssl_pattern.yaml'):
        super().__init__(zeek_logs_dir)
        try:
            with open(config_path, 'r') as f:
                self.config = yaml.safe_load(f)
        except (IOError, yaml.YAMLError) as e:
            logging.error(f"FATAL: Không thể tải tệp cấu hình '{config_path}': {e}")
            raise
    # ... (các hàm khác giữ nguyên) ...
    @property
    def collector_name(self) -> str:
        return "ssl"

    def _clean_output(self, data: Any) -> Any:
        if isinstance(data, dict):
            cleaned_data = {key: self._clean_output(value) for key, value in data.items()}
            return {key: value for key, value in cleaned_data.items() if value is not None and value != [] and value != {}}
        if isinstance(data, list):
            return [self._clean_output(item) for item in data if item is not None]
        return data

    def _get_sni_reputation(self, server_name: str) -> str:
        if not server_name: return "Unknown"
        extracted = tldextract.extract(server_name)
        registered_domain = f"{extracted.domain}.{extracted.suffix}"
        if registered_domain in self.config['reputation']['trusted_domains']:
            return self.config['reputation']['trusted_domains'][registered_domain]
        domain_parts = set(server_name.lower().split('.')) | set(server_name.lower().split('-'))
        if not set(self.config['reputation']['adware_keywords']).isdisjoint(domain_parts): return "Adware/Tracker"
        if not set(self.config['reputation']['benign_keywords']).isdisjoint(domain_parts): return "Likely Benign Infrastructure"
        return "Unknown Reputation"
    def collect(self, log_lines: List[str]) -> Dict[str, Any] | None:
        if not log_lines: return None

        # --- PHẦN 1: Thu thập bằng chứng thô ---
        # (Logic thu thập vẫn giữ nguyên)
        uids, ja3_hashes, ja3s_hashes, versions, ciphers = set(), set(), set(), set(), set()
        server_names, cert_chain_fps = set(), set()
        certificate_issues, all_validation_statuses = set(), set()
        weak_protocols_found, weak_ciphers_found = set(), set()
        total_duration = 0.0
        handshake_established = False

        for line in log_lines:
            try:
                log_entry = json.loads(line)
                
                uids.add(log_entry.get("uid"))
                if sn := log_entry.get("server_name"): server_names.add(sn)
                if j3 := log_entry.get("ja3"): ja3_hashes.add(j3)
                if j3s := log_entry.get("ja3s"): ja3s_hashes.add(j3s)
                if v := log_entry.get("version"): versions.add(v)
                if c := log_entry.get("cipher"): ciphers.add(c)
                if cfps := log_entry.get("cert_chain_fps"): cert_chain_fps.update(cfps)

                if log_entry.get('established', False): handshake_established = True
                total_duration += log_entry.get('duration', 0.0)

                if (v := log_entry.get('version')) and v in self.config['security']['weak_protocols']:
                    weak_protocols_found.add(v)
                if (c := log_entry.get('cipher')) and c in self.config['security']['weak_ciphers']:
                    weak_ciphers_found.add(c)
                
                if status := log_entry.get('validation_status', ''):
                    all_validation_statuses.add(status)
                    status_lower = status.lower()
                    if "self-signed" in status_lower: certificate_issues.add("Self-Signed Certificate")
                    if "unable to get local issuer" in status_lower: certificate_issues.add("Untrusted Chain")
                    if "has expired" in status_lower: certificate_issues.add("Expired Certificate")

            except (json.JSONDecodeError, KeyError) as e:
                logging.warning(f"Lỗi xử lý SSL log: {e}. Bỏ qua dòng log này.")
                continue


        if not (server_names or ja3_hashes): return None

        # # --- PHẦN 2: Phân tích và tạo các tín hiệu ---
        # # (Logic phân tích vẫn giữ nguyên)
        # main_server_name = next(iter(server_names), None)
        # server_reputation = self._get_sni_reputation(main_server_name)

        # certificate_status = "Invalid" if certificate_issues else "Trusted"
        # encryption_strength = "Weak" if weak_protocols_found or weak_ciphers_found else "Strong"

        # ja3_matches = {h: self.config['threat_intel']['known_malicious_ja3'].get(h) for h in ja3_hashes}
        # ja3s_matches = {h: self.config['threat_intel']['known_malicious_ja3s'].get(h) for h in ja3s_hashes}
        
        # threat_intel_analysis = {
        #     "ja3_match": any(ja3_matches.values()),
        #     "ja3s_match": any(ja3s_matches.values())
        # }

        # # --- PHẦN 3: Xây dựng output cuối cùng ---
        # analysis = {
        #     "server_reputation": server_reputation,
        #     "certificate_status": certificate_status,
        #     "encryption_strength": encryption_strength,
        #     "threat_intel_match": threat_intel_analysis,
        #     "handshake_status": "Successful" if handshake_established else "Failed"
        # }

        # statistics = {
        #     "connection_duration_sec": round(total_duration, 4)
        # }
        
        # ### <<< THAY ĐỔI LỚN: Tinh gọn lại khối evidence
        # evidence = {
        #     "server_names": sorted(list(server_names)),
        #     "tls_versions_used": sorted(list(versions)),
        #     "ciphers_used": sorted(list(ciphers)),
        #     "certificate_issues": sorted(list(certificate_issues)),
        #     "certificate_chain_fingerprints": sorted(list(cert_chain_fps)),
            
        #     # Cấu trúc mới, được làm giàu cho JA3/JA3S
        #     "ja3_details": [
        #         {"hash": h, "threat_name": ja3_matches.get(h)} for h in sorted(list(ja3_hashes))
        #     ],
        #     "ja3s_details": [
        #         {"hash": h, "threat_name": ja3s_matches.get(h)} for h in sorted(list(ja3s_hashes))
        #     ]
        # }
        
        # final_output = {
        #     "analysis": analysis,
        #     "statistics": statistics,
        #     "evidence": evidence
        # }
        
        # return self._clean_output(final_output)
        # --- PHẦN 2: Tối ưu hóa Phân tích & Tạo tín hiệu ---

        # Thay vì các chuỗi kết luận, chúng ta tạo ra các danh sách quan sát
        observed_cert_issues = sorted(list(certificate_issues))
        observed_weak_protocols = sorted(list(weak_protocols_found))
        observed_weak_ciphers = sorted(list(weak_ciphers_found))

        # Giữ lại logic Threat Intel vì nó khá rõ ràng
        ja3_matches = {h: self.config['threat_intel']['known_malicious_ja3'].get(h) for h in ja3_hashes}
        ja3s_matches = {h: self.config['threat_intel']['known_malicious_ja3s'].get(h) for h in ja3s_hashes}
        ja3_threat_name = next((name for name in ja3_matches.values() if name), None)
        ja3s_threat_name = next((name for name in ja3s_matches.values() if name), None)

        # --- PHẦN 3: Xây dựng output cuối cùng với "overall_assessment" ---

        # 1. Tạo câu đánh giá tổng thể (overall_assessment)
        assessment = "Likely Benign: No significant threat indicators found in the TLS session."
        high_confidence_threats = []

        if ja3_threat_name:
            high_confidence_threats.append(f"a JA3 hash matching '{ja3_threat_name}'")
        if ja3s_threat_name:
            high_confidence_threats.append(f"a JA3S hash matching '{ja3s_threat_name}'")

        medium_confidence_anomalies = []
        if "Self-Signed Certificate" in observed_cert_issues:
            medium_confidence_anomalies.append("a self-signed certificate")
        if "Untrusted Chain" in observed_cert_issues:
            medium_confidence_anomalies.append("an untrusted certificate chain")

        if high_confidence_threats:
            assessment = f"High Confidence Threat: Session contains strong indicators of malware, including {', '.join(high_confidence_threats)}."
        elif medium_confidence_anomalies:
            assessment = f"Suspicious Anomaly: Session involves anomalies like {', '.join(medium_confidence_anomalies)}, which could be malicious or misconfigured internal services. Further investigation is recommended."
        elif observed_weak_protocols or observed_weak_ciphers:
            assessment = "Informational: The session used weak encryption. This is a policy violation but not a direct indicator of a threat."

        # 2. Tạo khối analysis mới
        analysis = {
            "overall_assessment": assessment,
            "observed_certificate_issues": observed_cert_issues,
            "observed_weak_protocols": observed_weak_protocols,
            "observed_weak_ciphers": observed_weak_ciphers,
            "handshake_status": "Successful" if handshake_established else "Failed"
        }

        # statistics và evidence giữ nguyên cấu trúc cũ của bạn vì nó đã khá tốt
        statistics = {
            "connection_duration_sec": round(total_duration, 4)
        }

        evidence = {
            "server_names": sorted(list(server_names)),
            "tls_versions_used": sorted(list(versions)),
            "ciphers_used": sorted(list(ciphers)),
            "certificate_chain_fingerprints": sorted(list(cert_chain_fps)),
            "ja3_details": [
                {"hash": h, "threat_name": ja3_matches.get(h)} for h in sorted(list(ja3_hashes))
            ],
            "ja3s_details": [
                {"hash": h, "threat_name": ja3s_matches.get(h)} for h in sorted(list(ja3s_hashes))
            ]
        }

        final_output = {
            "analysis": analysis,
            "statistics": statistics,
            "evidence": evidence
        }

        return self._clean_output(final_output)