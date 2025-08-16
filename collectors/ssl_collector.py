import json
import logging
from typing import List, Dict, Any, Set

import yaml         # Thư viện để đọc tệp YAML
import tldextract   # Thư viện để phân tích tên miền

# Cấu hình logging cơ bản để ghi lại các lỗi
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
            raise  # Dừng chương trình nếu không có cấu hình

    @property
    def collector_name(self) -> str:
        return "ssl"

    def _get_sni_reputation(self, server_name: str) -> str:
        if not server_name: return "Unknown"
        
        # SỬA LỖI 1: Sử dụng tldextract để lấy tên miền gốc chính xác
        extracted = tldextract.extract(server_name)
        registered_domain = f"{extracted.domain}.{extracted.suffix}"
        
        # Kiểm tra tên miền gốc trong danh sách tin cậy
        if registered_domain in self.config['reputation']['trusted_domains']:
            return self.config['reputation']['trusted_domains'][registered_domain]

        # Kiểm tra từ khóa trong toàn bộ FQDN (linh hoạt hơn)
        domain_parts = set(server_name.lower().split('.')) | set(server_name.lower().split('-'))
        adware_keywords = set(self.config['reputation']['adware_keywords'])
        benign_keywords = set(self.config['reputation']['benign_keywords'])

        if not adware_keywords.isdisjoint(domain_parts): return "Adware/Tracker"
        if not benign_keywords.isdisjoint(domain_parts): return "Likely Benign Infrastructure"
        
        return "Unknown Reputation"

    def collect(self, log_lines: List[str]) -> Dict[str, Any] | None:
        if not log_lines: return None

        # --- PHẦN 1: Thu thập bằng chứng thô (Logic được làm lại) ---
        # SỬA LỖI 4: Không giả định thứ tự log, xử lý tuần tự
        
        # Thông tin tổng hợp của kết nối
        summary = {
            "uid": None, "source_ip": None, "dest_ip": None,
            "server_name": None, "ja3": None, "ja3s": None,
            "version": None, "cipher": None,
            "handshake_established": False, "duration": 0.0,
            "cert_chain_fps": None
        }
        
        # Các bằng chứng thu thập được qua nhiều log
        certificate_issues: Set[str] = set()
        all_validation_statuses: Set[str] = set()
        weak_protocol_evidence = None
        weak_cipher_evidence = None

        for line in log_lines:
            try:
                log_entry = json.loads(line)
                
                # SỬA LỖI 3: Cải thiện xử lý lỗi, không bỏ qua toàn bộ kết nối
                # Lấy các thông tin cơ bản một cách an toàn
                summary['uid'] = log_entry.get('uid', summary['uid'])
                if 'id.orig_h' in log_entry: summary['source_ip'] = log_entry['id.orig_h']
                if 'id.resp_h' in log_entry: summary['dest_ip'] = log_entry['id.resp_h']
                
                # Cập nhật các trường thông tin nếu chúng chưa có
                summary['server_name'] = log_entry.get('server_name') or summary['server_name']
                summary['ja3'] = log_entry.get('ja3') or summary['ja3']
                summary['ja3s'] = log_entry.get('ja3s') or summary['ja3s']
                summary['version'] = log_entry.get('version') or summary['version']
                summary['cipher'] = log_entry.get('cipher') or summary['cipher']
                summary['cert_chain_fps'] = log_entry.get('cert_chain_fps') or summary['cert_chain_fps']

                # Cập nhật các trường có thể thay đổi (lấy giá trị cuối cùng)
                if log_entry.get('established', False): summary['handshake_established'] = True
                if 'duration' in log_entry: summary['duration'] = log_entry['duration']

                # SỬA LỖI 2: Phát hiện Cipher/Protocol yếu bằng so khớp chính xác
                if (v := log_entry.get('version')) and v in self.config['security']['weak_protocols']:
                    weak_protocol_evidence = v
                if (c := log_entry.get('cipher')) and c in self.config['security']['weak_ciphers']:
                    weak_cipher_evidence = c
                
                # Thu thập tất cả các trạng thái xác thực chứng chỉ
                if status := log_entry.get('validation_status', ''):
                    all_validation_statuses.add(status)
                    status_lower = status.lower()
                    if "self-signed" in status_lower: certificate_issues.add("Self-Signed Certificate")
                    if "unable to get local issuer" in status_lower: certificate_issues.add("Untrusted Chain")
                    if "has expired" in status_lower: certificate_issues.add("Expired Certificate")

            except json.JSONDecodeError:
                logging.warning(f"Lỗi phân tích JSON cho UID {summary.get('uid', 'Unknown')}. Bỏ qua dòng log này.")
                continue # Tiếp tục xử lý các dòng log khác
            except KeyError as e:
                logging.warning(f"Thiếu key {e} trong log cho UID {summary.get('uid', 'Unknown')}. Bỏ qua dòng log này.")
                continue

        if not (summary['server_name'] or summary['ja3']):
            return None

        # --- PHẦN 2: Phân tích và tạo các tín hiệu ---
        server_reputation = self._get_sni_reputation(summary['server_name'])
        cert_status = f"Invalid ({', '.join(sorted(list(certificate_issues)))})" if certificate_issues else "Trusted"
        
        weaknesses = []
        if weak_protocol_evidence: weaknesses.append(f"Outdated Protocol: {weak_protocol_evidence}")
        if weak_cipher_evidence: weaknesses.append(f"Insecure Cipher: {weak_cipher_evidence}")
        
        encryption_strength = f"Weak ({'; '.join(weaknesses)})" if weaknesses else f"Strong (Using {summary['version']})"

        # SỬA LỖI 1: Phân tích cả JA3 và JA3S
        ja3_threat = self.config['threat_intel']['known_malicious_ja3'].get(summary['ja3'])
        ja3_match = f"JA3 Matched Malware: {ja3_threat}" if ja3_threat else "JA3 Not in Watchlist"
        
        ja3s_threat = self.config['threat_intel']['known_malicious_ja3s'].get(summary['ja3s'])
        ja3s_match = f"JA3S Matched C2 Server: {ja3s_threat}" if ja3s_threat else "JA3S Not in Watchlist"
        
        handshake_status = "Successful" if summary['handshake_established'] else "Failed"

        # --- PHẦN 3: Xây dựng output cuối cùng ---
        return {
            "identity": {
                "server_name": summary['server_name']
            },
            "analysis": {
                "server_reputation": server_reputation,
                "certificate_status": cert_status,
                "encryption_strength": encryption_strength,
                "ja3_threat_match": ja3_match,
                "ja3s_threat_match": ja3s_match, # Bổ sung tín hiệu JA3S
                "handshake_status": handshake_status
            },
            "statistics": {
                "connection_duration_sec": round(summary['duration'], 4) if summary['duration'] else 0.0
            },
            "evidence": {
                "ja3_hash": summary['ja3'],
                "ja3s_hash": summary['ja3s'],
                "tls_version": summary['version'],
                "tls_cipher": summary['cipher'],
                "raw_validation_statuses": sorted(list(all_validation_statuses)),
                "certificate_chain_fingerprints": summary['cert_chain_fps']
            }
        }