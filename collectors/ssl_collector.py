# FILE: collectors/ssl_collector.py

import subprocess
import json
import logging
from .base_collector import BaseCollector
from log_helper import find_log_files

class SslCollector(BaseCollector):
    """
    Collector chuyên thu thập và tóm tắt thông tin từ ssl.log.
    Nó trích xuất các thông tin định danh quan trọng như SNI, JA3, JA3S
    và đưa ra cảnh báo nếu phát hiện giao thức hoặc bộ mật mã yếu.
    """
    
    # Các phiên bản giao thức bị coi là yếu và không an toàn
    WEAK_PROTOCOLS = {'SSLv3', 'TLSv1.0', 'TLSv1.1'}
    
    # Các chuỗi con trong tên bộ mật mã cho thấy sự yếu kém
    # Ví dụ: 'TLS_RSA_WITH_RC4_128_MD5' chứa cả 'RC4' và 'MD5'
    WEAK_CIPHER_SUBSTRINGS = {'RC4', 'MD5', 'EXPORT', 'NULL', 'DES'}

    @property
    def collector_name(self) -> str:
        return "ssl"

    def collect(self, uid: str, alert_timestamp: float) -> dict | None:
        list_of_log_files = find_log_files(
            self.zeek_logs_dir, self.collector_name, alert_timestamp
        )
        if not list_of_log_files:
            return None

        all_matching_lines = []
        command = "grep"
        for log_file in list_of_log_files:
            try:
                result = subprocess.run(
                    [command, uid, log_file],
                    capture_output=True, text=True, check=False
                )
                if result.returncode <= 1 and result.stdout:
                    all_matching_lines.extend(result.stdout.strip().split('\n'))
            except (subprocess.CalledProcessError, FileNotFoundError):
                continue

        if not all_matching_lines:
            return None

        # --- KHỞI TẠO CÁC BIẾN ĐỂ LƯU KẾT QUẢ TÓM TẮT ---
        server_name_sni = None
        ja3_hash = None
        ja3s_hash = None
        tls_version = None
        weak_cipher_or_protocol_detected = False

        # --- LẶP QUA CÁC BẢN GHI ĐỂ TỔNG HỢP THÔNG TIN ---
        # Một kết nối có thể có nhiều bản ghi ssl.log, ta tổng hợp lại để lấy thông tin đầy đủ nhất
        for line in all_matching_lines:
            if not line: continue
            try:
                log_entry = json.loads(line)
                if log_entry.get('uid') != uid:
                    continue

                # Cập nhật các giá trị cốt lõi (giá trị cuối cùng sẽ được giữ lại)
                if log_entry.get('server_name'):
                    server_name_sni = log_entry['server_name']
                if log_entry.get('ja3'):
                    ja3_hash = log_entry['ja3']
                if log_entry.get('ja3s'):
                    ja3s_hash = log_entry['ja3s']
                if log_entry.get('version'):
                    tls_version = log_entry['version']
                
                # --- LOGIC PHÁT HIỆN ĐIỂM YẾU ---
                if not weak_cipher_or_protocol_detected:
                    # 1. Kiểm tra phiên bản giao thức
                    if tls_version in self.WEAK_PROTOCOLS:
                        weak_cipher_or_protocol_detected = True
                    
                    # 2. Kiểm tra bộ mật mã (nếu giao thức chưa bị coi là yếu)
                    if not weak_cipher_or_protocol_detected and 'cipher' in log_entry:
                        cipher_str = log_entry['cipher'].upper()
                        for weak_part in self.WEAK_CIPHER_SUBSTRINGS:
                            if weak_part in cipher_str:
                                weak_cipher_or_protocol_detected = True
                                break # Thoát khi đã tìm thấy điểm yếu

            except (json.JSONDecodeError, KeyError):
                continue

        # Chỉ trả về kết quả nếu có thông tin định danh hữu ích (SNI hoặc JA3)
        if not server_name_sni and not ja3_hash:
            return None
        
        return {
            "server_name_sni": server_name_sni,
            "ja3_hash": ja3_hash,
            "ja3s_hash": ja3s_hash,
            "tls_version": tls_version,
            # "weak_cipher_or_protocol_detected": weak_cipher_or_protocol_detected
        }