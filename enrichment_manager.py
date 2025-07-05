# security_onion_llm_project/enrichment_manager.py


import yaml
from datetime import datetime

from config import ZEEK_LOGS_DIR, CONN_LOG_TIME_WINDOW_SECONDS, ENRICHMENT_RULES_PATH
from log_helper import find_log_files
from collectors.conn_collector import ConnCollector
from collectors.dns_collector import DnsCollector
from collectors.http_collector import HttpCollector
from collectors.files_collector import FilesCollector
from collectors.ssl_collector import SslCollector # Bạn sẽ thêm các collector khác ở đây


class EnrichmentManager:
    def __init__(self):
        # 1. Khởi tạo tất cả các collector có thể có
        self.conn_collector = ConnCollector(ZEEK_LOGS_DIR, CONN_LOG_TIME_WINDOW_SECONDS)
        
        self.all_collectors = [
            HttpCollector(ZEEK_LOGS_DIR),
            DnsCollector(ZEEK_LOGS_DIR),
            FilesCollector(ZEEK_LOGS_DIR),
            SslCollector(ZEEK_LOGS_DIR), # Ví dụ
        ]
        self.collectors_map = {c.collector_name: c for c in self.all_collectors}
        
        # 2. Đọc và phân tích file quy tắc YAML
        try:
            with open(ENRICHMENT_RULES_PATH, 'r') as f:
                self.rules = yaml.safe_load(f)
        except (FileNotFoundError, yaml.YAMLError):
            # Nếu file không tồn tại hoặc lỗi, dùng một quy tắc rỗng
            self.rules = {'primary_evidence_map': {}}

    def _build_llm_prompt(self, alert: dict, conn_summary: dict, primary_evidence: dict, secondary_evidence: dict) -> str:
        """
        Lắp ráp tất cả các mảnh thông tin thành một prompt hoàn chỉnh cho LLM.
        """
        # Hàm tiện ích nội bộ để định dạng các khối bằng chứng
        def format_evidence(evidence_dict: dict) -> str:
            if not evidence_dict:
                return "Không có."
            
            output_parts = []
            for collector_name, data in evidence_dict.items():
                lines = [f"[{collector_name.upper()}]:"]
                for key, value in data.items():
                    # Định dạng danh sách cho dễ đọc
                    if isinstance(value, list) and not value:
                        formatted_value = "[]"
                    elif isinstance(value, list):
                        formatted_value = ", ".join(map(str, value))
                    else:
                        formatted_value = value
                    lines.append(f"  - {key}: {formatted_value}")
                output_parts.append("\n".join(lines))
            return "\n\n".join(output_parts)

        primary_str = format_evidence(primary_evidence)
        secondary_str = format_evidence(secondary_evidence)
        
        # Tính toán các thông tin tóm tắt
        alert_timestamp = alert.get('@timestamp', 'N/A')
        alert_uuid = alert.get('log', {}).get('id', {}).get('uid', "N/A")
        alert_name = alert.get('rule', {}).get('name', 'N/A')
        alert_category = alert.get('rule', {}).get('category', 'N/A')
        alert_severity = alert.get('rule', {}).get('severity', 'N/A')
        connection_str = f"{alert.get('source', {}).get('ip')}:{alert.get('source', {}).get('port')} -> {alert.get('destination', {}).get('ip')}:{alert.get('destination', {}).get('port')} ({alert.get('network',{}).get('transport', 'tcp').upper()})"
        connection_state = f"{conn_summary.get('conn_state', 'N/A')}" if conn_summary else "N/A"
        connection_service = f"{conn_summary.get('service', 'N/A')}" if conn_summary else "N/A"
        connection_duration = f"{conn_summary.get('duration', 'N/A')} giây" if conn_summary else "N/A"
        total_bytes = ((conn_summary.get('orig_bytes', 0) or 0) + (conn_summary.get('resp_bytes', 0) or 0)) if conn_summary else 0
        connnection_traffic = f"{total_bytes / 1024:.2f} KB" if total_bytes > 0 else "N/A"


        # Sử dụng f-string để tạo template prompt cuối cùng
        prompt = f"""

# CẢNH BÁO GỐC: 
- Cảnh báo: {alert_name}
- Phân loại cảnh báo: {alert_category}
- Mức độ cảnh báo: {alert_severity}
- Thời gian: {alert_timestamp}
- UUID: {alert_uuid}

# KẾT NỐI CHÍNH:
- Kết nối: {connection_str}
- Thời gian kết nối: {connection_duration}
- Trạng thái kết nối: {connection_state}
- Dịch vụ: {connection_service}
- Tổng dung lượng trao đổi: {connnection_traffic}

# BẰNG CHỨNG ĐÃ THU THẬP (ENRICHED EVIDENCE)
## BẰNG CHỨNG SƠ CẤP (QUAN TRỌNG NHẤT):
{primary_str}

## BẰNG CHỨNG THỨ CẤP (THÔNG TIN BỔ SUNG):
{secondary_str}

"""
        return prompt.strip()

    def enrich_and_prompt(self, suricata_alert: dict) -> str:
        """
        Đây là phương thức công khai chính, điều phối toàn bộ quá trình.
        """
        # 1. Tìm UID và thông tin kết nối cơ bản
        uid, conn_summary = self.conn_collector.find_connection(suricata_alert)
        if not uid:
            # Nếu không tìm thấy UID, vẫn xây dựng prompt với thông tin hạn chế
            return self._build_llm_prompt(suricata_alert, {}, {}, {})
        
        alert_timestamp = self.conn_collector._extract_timestamp_from_alert(suricata_alert)
        if alert_timestamp is None:
            # Nếu không lấy được timestamp, không thể tiếp tục
            return None, None
        
    # 2. Điều phối tất cả collector để thu thập bằng chứng
        all_evidence = {}
        for collector in self.all_collectors:
            result = collector.collect(uid, alert_timestamp)
            if result:
                all_evidence[collector.collector_name] = result

        # 3. Phân loại bằng chứng dựa trên quy tắc
        primary_evidence = {}
        secondary_evidence = {}
        alert_signature = suricata_alert.get('rule', {}).get('name', '').upper()
        
        primary_collectors_names = set()
        for keyword, collectors in self.rules.get('primary_evidence_map', {}).items():
            if keyword.upper() in alert_signature:
                primary_collectors_names.update(collectors)

        for name, data in all_evidence.items():
            if name in primary_collectors_names:
                primary_evidence[name] = data
            else:
                secondary_evidence[name] = data

        # 4. Xây dựng và trả về prompt cuối cùng
        return self._build_llm_prompt(suricata_alert, conn_summary or {}, primary_evidence, secondary_evidence)