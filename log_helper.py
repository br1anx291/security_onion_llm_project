# security_onion_llm_project/log_helper.py

import os
import logging
import re
from datetime import datetime, time
from datetime import datetime, timezone

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

def find_log_files(base_dir: str, log_type: str, alert_timestamp: float) -> list[str]:
    """
    Tìm tất cả các file log có khả năng liên quan cho một loại log và thời điểm cụ thể.
    Hàm này sẽ tìm trong cả thư mục log lịch sử (theo ngày/giờ) và thư mục 'current',
    sau đó trả về một danh sách kết hợp các file tìm được.
    """
    found_files = []
    
    try:
        dt_object = datetime.fromtimestamp(alert_timestamp, tz=timezone.utc)
        alert_time = dt_object.time().replace(microsecond=0)
    except (TypeError, ValueError) as e:
        logging.error(f"Timestamp không hợp lệ: {alert_timestamp}. Lỗi: {e}")
        return []

    # === PHẦN 1: TÌM KIẾM TRONG LOG LỊCH SỬ (THƯ MỤC THEO NGÀY) ===
    date_folder_name = dt_object.strftime('%Y-%m-%d')
    path_to_scan = os.path.join(base_dir, date_folder_name)
    
    if os.path.isdir(path_to_scan):
        time_pattern = re.compile(r'\.(\d{2}:\d{2}:\d{2})-(\d{2}:\d{2}:\d{2})\.log')
        try:
            for filename in os.listdir(path_to_scan):
                if not filename.startswith(f"{log_type}."):
                    continue
                
                match = time_pattern.search(filename)
                if not match:
                    continue
                
                start_time_str, end_time_str = match.groups()
                try:
                    start_time = time.fromisoformat(start_time_str)
                    end_time = time.fromisoformat(end_time_str)
                    
                    if start_time <= alert_time < end_time:
                        full_path = os.path.join(path_to_scan, filename)
                        logging.info(f"Đã tìm thấy file log lịch sử: {full_path}")
                        found_files.append(full_path)
                        # Chỉ có một file lịch sử khớp tại một thời điểm, nên dừng tìm kiếm ở đây
                        break
                except ValueError:
                    continue
        except FileNotFoundError:
            pass # Thư mục có thể tồn tại nhưng không thể đọc
    else:
        logging.warning(f"Không tìm thấy thư mục log lịch sử cho ngày {date_folder_name}.")

    # === PHẦN 2: LUÔN TÌM KIẾM TRONG THƯ MỤC 'CURRENT' ===
    current_log_dir = os.path.join(base_dir, "current")
    if os.path.isdir(current_log_dir):
        try:
            for filename in os.listdir(current_log_dir):
                # Tìm file như http.log, dns.log, ...
                if filename.startswith(f"{log_type}.") and filename.endswith(".log"):
                    full_path = os.path.join(current_log_dir, filename)
                    logging.info(f"Đã tìm thấy file log 'current': {full_path}")
                    found_files.append(full_path)
        except OSError as e:
            logging.error(f"Lỗi khi truy cập thư mục 'current': {e}")
            
    # === PHẦN 3: TRẢ VỀ KẾT QUẢ TỔNG HỢP ===
    if not found_files:
        logging.warning(f"Không tìm thấy file log nào cho '{log_type}' tại thời điểm {alert_time} trong cả thư mục lịch sử và 'current'.")
    
    # Dùng set để đảm bảo không có đường dẫn file nào bị trùng lặp
    return sorted(list(set(found_files)))