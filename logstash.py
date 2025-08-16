# get_redis_logs_v4_filter.py
import redis
import sys
import logging
import json
import fnmatch # Thư viện để so khớp mẫu có dấu *

# --- Cấu hình logging ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# ==============================================================================
# PHẦN CẤU HÌNH
# ==============================================================================
REDIS_HOST = "localhost"
REDIS_PORT = 9696
REDIS_PASSWORD = "7w7th5JF9fzbiRsK3CVv"
LOG_KEY = "logstash:unparsed"
WAIT_TIMEOUT = 10

# Tên file để lưu các log đã được lọc
OUTPUT_FILE = "filtered_logs.txt"

# === BỘ LỌC CỦA BẠN ===
# Danh sách các mẫu đường dẫn file bạn muốn giữ lại.
# Dấu * sẽ khớp với bất kỳ chuỗi ký tự nào.
FILTER_PATTERNS = [
    "/nsm/zeek/logs/current/conn.log",
    "/nsm/zeek/logs/current/dns.log",
    "/nsm/suricata/eve-*.json"
]
# ==============================================================================

def main():
    logging.info(f"--- Bắt đầu script v4 (Lọc log từ Redis) ---")
    logging.info(f"Các mẫu lọc được áp dụng: {FILTER_PATTERNS}")
    
    try:
        logging.info(f"Đang kết nối tới Redis tại {REDIS_HOST}:{REDIS_PORT} với SSL...")
        redis_client = redis.Redis(
            host=REDIS_HOST, port=REDIS_PORT, password=REDIS_PASSWORD,
            db=0, socket_connect_timeout=5, ssl=True, ssl_cert_reqs=None
        )
        redis_client.ping()
        logging.info(">>> Kết nối Redis qua SSL thành công! <<<")
    except Exception as e:
        logging.error(f"LỖI KẾT NỐI: {e}")
        sys.exit(1)

    logging.info(f"Bắt đầu lắng nghe và lọc log từ key '{LOG_KEY}'.")
    logging.info("Nhấn Ctrl+C để dừng script.")

    try:
        while True:
            logging.info(f"Đang chờ log mới trong {WAIT_TIMEOUT} giây...")
            packed_data = redis_client.blpop(LOG_KEY, timeout=WAIT_TIMEOUT)
            
            if not packed_data:
                logging.info("... Không có log mới. Vẫn đang lắng nghe ... ❤️")
                continue

            # === BỘ LỌC BẮT ĐẦU HOẠT ĐỘNG TẠI ĐÂY ===
            try:
                log_string = packed_data[1].decode('utf-8')
                log_json = json.loads(log_string) # Parse chuỗi JSON lớn

                # Dùng .get() để tránh lỗi nếu không có key
                file_path = log_json.get('log', {}).get('file', {}).get('path')

                if not file_path:
                    logging.warning("Log không có trường 'log.file.path', bỏ qua.")
                    continue

                # So sánh đường dẫn file với từng mẫu trong bộ lọc
                is_match_found = False
                for pattern in FILTER_PATTERNS:
                    if fnmatch.fnmatch(file_path, pattern):
                        logging.info(f"✅ MATCH FOUND: '{file_path}' khớp với mẫu '{pattern}'. Đang lưu log...")
                        
                        # Mở file và ghi log đã khớp
                        with open(OUTPUT_FILE, 'a', encoding='utf-8') as f:
                            f.write(log_string + '\n') # Ghi lại toàn bộ chuỗi JSON gốc
                        
                        is_match_found = True
                        break # Đã khớp, không cần kiểm tra các mẫu khác

                if not is_match_found:
                    logging.info(f"❌ NO MATCH: '{file_path}' không khớp mẫu nào. Bỏ qua.")

            except json.JSONDecodeError:
                logging.error("Lỗi parse JSON. Log có thể bị lỗi định dạng. Bỏ qua.")
            except Exception as e:
                logging.error(f"Lỗi khi xử lý log: {e}. Bỏ qua log này.")
            
    except KeyboardInterrupt:
        logging.warning("\nScript đã dừng bởi người dùng.")
        sys.exit(0)

if __name__ == "__main__":
    main()