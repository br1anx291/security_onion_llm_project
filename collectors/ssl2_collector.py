# FILE: collectors/ssl_collector.py

import json
from typing import List, Dict, Any, Set

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
    WEAK_PROTOCOLS = {'SSLv3', 'TLSv10', 'TLSv11'}
    WEAK_CIPHER_SUBSTRINGS = {'RC4', 'MD5', 'EXPORT', 'NULL', 'DES', '3DES'}
    KNOWN_MALICIOUS_JA3 = {
        "e7d4dd046396654b42318a6bd69c5e27": "TrickBot",
        "d8da247a3e3110522e4350f9684b553d": "Cobalt Strike",
        "4d7a22491b84a27776107386818e3a89": "Metasploit",
        "a95cf29d11593465851457e4235a4203": "Emotet"
    }
    
    KNOWN_DOMAINS = {
        "code.jquery.com": "Trusted CDN", "google.com": "Trusted Provider",
        "microsoft.com": "Trusted Provider", "ubuntu.com": "Trusted Provider",
        "archive.ubuntu.com": "Trusted Provider", "connect.facebook.net": "Trusted Provider",
        "use.typekit.net": "Trusted CDN"
    }
    ADWARE_KEYWORDS = {'ads', 'adserve', 'tracker', 'analytics', 'metrics', 'pixel', 'pubmatic', 'algovid', 'sitescout'}
    BENIGN_KEYWORDS = {'cdn', 'static', 'assets', 'api', 'content', 'images', 'font', 'adobe', 'akamai', 'cloud', 'aws'}
    
    @property
    def collector_name(self) -> str:
        return "ssl"

    def _get_sni_reputation(self, server_name: str) -> str:
        if not server_name: return "Unknown"
        if server_name in self.KNOWN_DOMAINS: return self.KNOWN_DOMAINS[server_name]
        
        domain_parts = set(server_name.lower().split('.'))
        if not self.ADWARE_KEYWORDS.isdisjoint(domain_parts): return "Adware/Tracker"
        if not self.BENIGN_KEYWORDS.isdisjoint(domain_parts): return "Likely Benign Infrastructure"
        
        return "Unknown Reputation"

    def collect(self, log_lines: List[str]) -> Dict[str, Any] | None:
        if not log_lines: return None

        # --- PHẦN 1: Thu thập bằng chứng thô ---
        server_name, ja3, ja3s = None, None, None
        version, cipher, validation_status, cert_chain_fps = None, None, None, None
        weak_protocol, weak_cipher = None, None
        certificate_issues: Set[str] = set()
        handshake_established, duration = None, None
        uid, source_ip, dest_ip = None, None, None

        try:
            # Lấy thông tin tổng hợp từ dòng log cuối cùng
            last_log = json.loads(log_lines[-1])
            uid = last_log.get('uid'); source_ip = last_log.get('id.orig_h'); dest_ip = last_log.get('id.resp_h')
            server_name = last_log.get('server_name'); ja3 = last_log.get('ja3'); ja3s = last_log.get('ja3s')
            version = last_log.get('version'); cipher = last_log.get('cipher')
            handshake_established = last_log.get('established', False); duration = last_log.get('duration')
            cert_chain_fps = last_log.get('cert_chain_fps')
            
            # Quét tất cả các dòng log để tìm bằng chứng về điểm yếu hoặc lỗi
            for line in log_lines:
                log_entry = json.loads(line)
                if not weak_protocol and (v := log_entry.get('version')) in self.WEAK_PROTOCOLS: weak_protocol = v
                if not weak_cipher and (c := log_entry.get('cipher')) and any(w in c.upper() for w in self.WEAK_CIPHER_SUBSTRINGS):
                    weak_cipher = c
                if status := log_entry.get('validation_status', ''):
                    validation_status = status # Ghi nhận trạng thái validation cuối cùng
                    status_lower = status.lower()
                    if "self-signed" in status_lower: certificate_issues.add("Self-Signed Certificate")
                    if "unable to get local issuer" in status_lower: certificate_issues.add("Untrusted Chain")
                    if "has expired" in status_lower: certificate_issues.add("Expired Certificate")
        except (json.JSONDecodeError, IndexError, KeyError): return None

        if not server_name and not ja3: return None

        # --- PHẦN 2: Phân tích và tạo các tín hiệu ---
        
        server_reputation = self._get_sni_reputation(server_name)
        cert_status = f"Invalid ({', '.join(sorted(list(certificate_issues)))})" if certificate_issues else "Trusted (No validation issues found)"
        
        weakness = []
        if weak_protocol: weakness.append(f"Outdated Protocol: {weak_protocol}")
        if weak_cipher: weakness.append(f"Insecure Cipher used")
        if weakness: encryption_strength = f"Weak ({'; '.join(weakness)})"
        else: encryption_strength = f"Strong (Using {version})" if version else "Unknown (Cipher/Version not negotiated)"
            
        if ja3 and (threat := self.KNOWN_MALICIOUS_JA3.get(ja3)):
            ja3_match = f"JA3 Matched Malware Watchlist: {threat}"
        else: ja3_match = "JA3 Not Found in Local Watchlist"
        
        handshake_status = "Successful" if handshake_established else "Failed"

        # --- PHẦN 3: Xây dựng output cuối cùng theo cấu trúc chuẩn ---
        
        identity = {
                    "server_name": server_name}
        
        analysis = {
            "server_reputation": server_reputation,
            "certificate_status": cert_status,
            "encryption_strength": encryption_strength,
            "ja3_threat_match": ja3_match,
            "handshake_status": handshake_status
        }
        
        statistics = {"connection_duration_sec": round(duration, 4) if duration else 0.0}
        
        evidence = {}
        if ja3: evidence["ja3_hash"] = ja3
        if ja3s: evidence["ja3s_hash"] = ja3s
        if version: evidence["tls_version"] = version
        if cipher: evidence["tls_cipher"] = cipher
        if validation_status: evidence["raw_validation_status"] = validation_status
        if cert_chain_fps: evidence["certificate_chain_fingerprints"] = cert_chain_fps

        final_output = {}
        if identity: final_output["identity"] = identity
        if analysis: final_output["analysis"] = analysis
        if statistics and duration is not None: final_output["statistics"] = statistics
        if evidence: final_output["evidence"] = evidence
            
        return final_output if final_output else None