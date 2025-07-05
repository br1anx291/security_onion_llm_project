
        
# collectors/dns_collector.py

import subprocess
import json
import math
from collections import Counter
from .base_collector import BaseCollector
from log_helper import find_log_files



class DnsCollector(BaseCollector):
    
        # --- Các hằng số để tinh chỉnh ---
    SUSPICIOUS_QTYPES = {'*', 'TXT'}
    FAILURE_RCODES = {'NXDOMAIN', 'SERVFAIL'}
    LOW_TTL_THRESHOLD = 60  # Dưới 60 giây được coi là thấp
    HIGH_ENTROPY_THRESHOLD = 2.8 # Ngưỡng entropy để phát hiện DGA  https://arxiv.org/pdf/2304.07943
    # 
    
    @property
    def collector_name(self) -> str:
        return "dns"
    
    def _calculate_shannon_entropy(self, text: str) -> float:
        """Tính toán entropy Shannon cho một chuỗi. Entropy cao cho thấy sự ngẫu nhiên."""
        if not text:
            return 0.0
        
        # Đếm số lần xuất hiện của mỗi ký tự
        counts = Counter(text)
        text_len = len(text)
        
        # Tính toán entropy
        entropy = 0.0
        for count in counts.values():
            p_x = count / text_len
            entropy -= p_x * math.log2(p_x)
            
        return entropy
    
    
    def collect(self, uid: str, alert_timestamp: float) -> dict | None:
        list_of_log_files = find_log_files(
            self.zeek_logs_dir, "dns", alert_timestamp
        )
        if not list_of_log_files:
            return None

        all_matching_lines = []
        
        # THAY ĐỔI: Lặp qua danh sách đường dẫn (string)
        # và lệnh grep luôn được gán là "grep"
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
        
 # --- KHỞI TẠO CÁC BIẾN ĐỂ TÍNH TOÁN TÍN HIỆU ---
        distinct_queries = set()
        distinct_answers = set()
        
        total_queries = 0
        failed_queries_count = 0
        suspicious_qtypes_present = False
        low_ttl_detected = False
        high_entropy_domain_detected = False

        # --- BẮT ĐẦU VÒNG LẶP PHÂN TÍCH ---
        for line in all_matching_lines:
            if not line: continue
            try:
                log_entry = json.loads(line)
                
                # Chỉ xử lý các log khớp chính xác UID
                if log_entry.get('uid') != uid:
                    continue

                total_queries += 1

                # 1. Kiểm tra failed_queries_ratio
                if log_entry.get('rcode_name') in self.FAILURE_RCODES:
                    failed_queries_count += 1

                # 2. Kiểm tra suspicious_qtypes_present
                if log_entry.get('qtype_name') in self.SUSPICIOUS_QTYPES:
                    suspicious_qtypes_present = True

                # 3. Kiểm tra low_ttl_detected
                if not low_ttl_detected: # Chỉ kiểm tra nếu chưa phát hiện
                    ttls = log_entry.get('TTLs', [])
                    if ttls:
                        for ttl in ttls:
                            if ttl < self.LOW_TTL_THRESHOLD:
                                low_ttl_detected = True
                                break # Thoát khỏi vòng lặp TTL khi đã phát hiện

                # # 4. Kiểm tra high_entropy_domain_detected
                # query = log_entry.get('query')
                # if query and not high_entropy_domain_detected:
                #     distinct_queries.add(query)
                #     entropy = self._calculate_shannon_entropy(query.split('.')[0]) # Chỉ tính entropy cho subdomain
                #     if entropy > self.HIGH_ENTROPY_THRESHOLD:
                #         high_entropy_domain_detected = True
                        
                query = log_entry.get('query')
                if query:
                    distinct_queries.add(query)     
                               
                # Thu thập câu trả lời để lấy mẫu
                if 'answers' in log_entry and log_entry['answers']:
                    distinct_answers.update(log_entry['answers'])

            except (json.JSONDecodeError, KeyError):
                continue

        if total_queries == 0:
            return None
        
        # --- TÍNH TOÁN KẾT QUẢ CUỐI CÙNG ---
        failed_ratio = (failed_queries_count / total_queries) if total_queries > 0 else 0.0

        # --- TRẢ VỀ BẢN TÓM TẮT THÔNG MINH ---
        return {
            "total_queries": total_queries,
            "distinct_queries_count": len(distinct_queries),
            "distinct_queries": sorted(list(distinct_queries)),
            
            "distinct_answers_count": len(distinct_answers),
            "distinct_answers": sorted(list(distinct_answers)),
            # # === 4 TÍN HIỆU QUAN TRỌNG ===
            # "failed_queries_ratio": round(failed_ratio, 2),
            # "suspicious_qtypes_present": suspicious_qtypes_present,
            # "low_ttl_detected": low_ttl_detected,
            # "high_entropy_domain_detected": high_entropy_domain_detected
        }
        
        
        
"""

### **Mô tả các Giá trị Đầu ra của `DnsCollector`**

Lớp `DnsCollector` phân tích các bản ghi `dns.log` liên quan đến một kết nối và trả về một dictionary chứa các thông số thống kê và các tín hiệu an ninh đã được xử lý. Các giá trị này được chia thành hai nhóm chính:

#### **A. Các tham số Thống kê Tổng quan**

Nhóm này cung cấp một cái nhìn tổng thể về quy mô và nội dung của các hoạt động DNS.

* **`total_queries`**
    * **Mô tả:** Tổng số lượng bản ghi `dns.log` được tìm thấy và phân tích cho kết nối này.
    * **Kiểu dữ liệu:** `Integer`.
    * **Ý nghĩa trong Phân tích An ninh:** Cho biết mật độ của hoạt động DNS. Một con số cao bất thường có thể chỉ ra các hành vi như "DNS storm" hoặc DGA brute-forcing.

* **`distinct_queries_count`**
    * **Mô tả:** Số lượng các tên miền (domain name) **duy nhất** đã được truy vấn.
    * **Kiểu dữ liệu:** `Integer`.
    * **Ý nghĩa trong Phân tích An ninh:** So sánh với `total_queries`. Nếu `total_queries` rất cao nhưng `distinct_queries_count` lại thấp, điều đó có nghĩa là client đang truy vấn lặp đi lặp lại một vài tên miền.

* **`distinct_queries`**
    * **Mô tả:** Một danh sách (đã được sắp xếp) chứa các tên miền **duy nhất** đã được truy vấn.
    * **Kiểu dữ liệu:** `List[str]`.
    * **Ý nghĩa trong Phân tích An ninh:** Đây là dữ liệu thô quan trọng nhất, cho phép nhà phân tích kiểm tra trực tiếp các tên miền để tìm các dấu hiệu đáng ngờ (TLD lạ, tên miền ngẫu nhiên, v.v.).

* **`distinct_answers_count`**
    * **Mô tả:** Số lượng các câu trả lời (IP, CNAME) **duy nhất** nhận được.
    * **Kiểu dữ liệu:** `Integer`.
    * **Ý nghĩa trong Phân tích An ninh:** Cung cấp một thước đo về sự đa dạng của các máy chủ mà tên miền phân giải tới.

* **`distinct_answers`**
    * **Mô tả:** Một danh sách (đã được sắp xếp) chứa các câu trả lời **duy nhất**.
    * **Kiểu dữ liệu:** `List[str]`.
    * **Ý nghĩa trong Phân tích An ninh:** Cho phép nhà phân tích kiểm tra các địa chỉ IP hoặc CNAME này với các nguồn tin tức tình báo về mối đe dọa (Threat Intelligence).

---

#### **B. Các Tín hiệu Phân tích An ninh (Security Analysis Signals)**

Đây là những giá trị đã được "thông minh hóa", đóng vai trò là các cờ báo hiệu hành vi bất thường, giúp tiết kiệm thời gian phân tích và token cho LLM.

* **`failed_queries_ratio`**
    * **Mô tả:** Tỷ lệ phần trăm các truy vấn DNS bị thất bại (có mã trả về là `NXDOMAIN` hoặc `SERVFAIL`) trên tổng số truy vấn.
    * **Kiểu dữ liệu:** `Float` (giá trị từ 0.0 đến 1.0).
    * **Ý nghĩa trong Phân tích An ninh:** **Một trong những chỉ số mạnh nhất để phát hiện Domain Generation Algorithms (DGA)**. Malware sử dụng DGA thường thử hàng loạt tên miền cho đến khi tìm thấy máy chủ C2. Hành vi này tạo ra một tỷ lệ truy vấn thất bại rất cao (ví dụ: > 0.5).

* **`suspicious_qtypes_present`**
    * **Mô tả:** Một cờ báo hiệu (`True`/`False`). Giá trị là `True` nếu có ít nhất một truy vấn sử dụng loại (qtype) được coi là đáng ngờ, ví dụ như `TXT` hoặc `ANY`.
    * **Kiểu dữ liệu:** `Boolean`.
    * **Ý nghĩa trong Phân tích An ninh:** Báo hiệu việc sử dụng DNS một cách không thông thường. Truy vấn `TXT` thường được lạm dụng để truyền lệnh điều khiển (C2) hoặc trích xuất dữ liệu. Truy vấn `ANY` thường được sử dụng trong giai đoạn do thám, thu thập thông tin.

* **`low_ttl_detected`**
    * **Mô tả:** Một cờ báo hiệu (`True`/`False`). Giá trị là `True` nếu có bất kỳ câu trả lời DNS nào có giá trị Time-To-Live (TTL) thấp hơn ngưỡng đã định (mặc định là 60 giây).
    * **Kiểu dữ liệu:** `Boolean`.
    * **Ý nghĩa trong Phân tích An ninh:** **Chỉ số kinh điển của kỹ thuật Fast-Flux DNS**. Kẻ tấn công sử dụng TTL thấp để thay đổi địa chỉ IP của máy chủ độc hại một cách liên tục, gây khó khăn cho việc ngăn chặn dựa trên IP. Cờ này giúp tự động phát hiện kỹ thuật né tránh đó.

* **`high_entropy_domain_detected`**
    * **Mô tả:** Một cờ báo hiệu (`True`/`False`). Giá trị là `True` nếu có ít nhất một tên miền truy vấn có độ ngẫu nhiên (Shannon entropy) cao hơn ngưỡng (mặc định là 3.5).
    * **Kiểu dữ liệu:** `Boolean`.
    * **Ý nghĩa trong Phân tích An ninh:** **Một chỉ số mạnh khác để phát hiện DGA**. Các tên miền do máy tạo ra (ví dụ: `k2gih39d9a1.com`) thường có độ ngẫu nhiên cao, khác với tên miền do người đặt (ví dụ: `google.com`). Cờ này giúp tự động nhận diện các tên miền trông như rác và đáng ngờ.

---

Hy vọng bản mô tả chi tiết này sẽ giúp bạn trong việc viết báo cáo.
"""        