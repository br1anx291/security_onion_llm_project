from elasticsearch import Elasticsearch
from elasticsearch_dsl import Search
from datetime import datetime, timezone
import urllib3
import subprocess
import time
import logging
import os
import pandas as pd
import numpy as np
import pytz

from config import (
    REMOTE_HOST, 
    REMOTE_USERNAME,
    SSH_TUNNEL_LOCAL_PORT,
    SSH_TUNNEL_REMOTE_PORT, 
    ELASTIC_HOST, 
    ELASTIC_USER, 
    ELASTIC_PASS, 
    ALERT_OUTPUT_PATH,
    ALERT_SEVERITY
)


# Setup logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
# --- CÁC HÀM GỐC GIỮ NGUYÊN ---
def start_ssh_tunnel():
    try:
        local_port = SSH_TUNNEL_LOCAL_PORT
        remote_port = SSH_TUNNEL_REMOTE_PORT
        ssh_target = f"{REMOTE_USERNAME}@{REMOTE_HOST}"
        logging.info(f"Starting SSH tunnel: localhost:{local_port} -> {ssh_target}:{remote_port}")
        subprocess.Popen(['ssh', '-N', '-L', f'{local_port}:localhost:{remote_port}', ssh_target])
        time.sleep(5)
        logging.info("SSH tunnel established successfully.")
    except Exception as e:
        logging.error(f"Error starting SSH tunnel: {e}")

def connect_elasticsearch():
    try:
        es = Elasticsearch([ELASTIC_HOST], ca_certs=False, verify_certs=False, basic_auth=(ELASTIC_USER, ELASTIC_PASS))
        if es.ping():
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            logging.info("Connected to Elasticsearch.")
            return es
        return None
    except Exception as e:
        logging.error(f"Elasticsearch connection error: {e}")
        return None

# --- HÀM retrieve_alerts ĐÃ ĐƯỢC CẬP NHẬT ---
# Chấp nhận cả start_time và end_time để truy vấn theo một khoảng thời gian cụ thể
def retrieve_alerts(es, severity, start_time=None, end_time=None):
    """
    Truy vấn các cảnh báo Suricata từ Elasticsearch trong một khoảng thời gian.
    """
    try:
        search_context = Search(using=es, index='*logs-*') \
            .query("query_string", query="event.module:suricata") \
            .filter("terms", **{"rule.severity": severity})

        # Xây dựng bộ lọc khoảng thời gian một cách linh hoạt
        time_range_filter = {}
        if start_time:
            time_range_filter['gte'] = start_time # gte: greater than or equal to
        if end_time:
            time_range_filter['lt'] = end_time   # lt: less than

        if time_range_filter:
            search_context = search_context.filter('range', **{'@timestamp': time_range_filter})

        # Sắp xếp để đảm bảo thứ tự
        search_context = search_context.sort('@timestamp')
        
        # Sử dụng .scan() để lấy tất cả kết quả, không bị giới hạn 10,000
        alerts_list = [d.to_dict() for d in search_context.scan()]
        
        if not alerts_list:
            return pd.DataFrame() # Trả về DataFrame rỗng nếu không có alert

        return pd.DataFrame(alerts_list)

    except Exception as e:
        logging.error(f"Error retrieving alerts: {e}")
        return None


if __name__ == "__main__":
    POLL_INTERVAL = 10
    
    start_ssh_tunnel()
    es = connect_elasticsearch()

    if not es:
        logging.error("Cannot proceed without Elasticsearch connection. Exiting.")
        exit()
    
    logging.info(f"Starting alert monitoring. Checking every {POLL_INTERVAL} seconds for new alerts.")
    logging.info("New alerts will be appended to the daily log file.")

    # --- THAY ĐỔI 1: Các biến trạng thái mới ---
    # Lưu lại timestamp của alert cuối cùng đã xử lý
    last_timestamp_processed = None 
    # Lưu lại đường dẫn file của ngày đang chạy để phát hiện khi sang ngày mới
    current_daily_log_path = None

    # Xác định múi giờ địa phương
    local_tz = pytz.timezone('Asia/Ho_Chi_Minh') 

    try:
        while True:
            # --- LOGIC XÁC ĐỊNH FILE VÀ KHOẢNG THỜI GIAN (ĐÃ VIẾT LẠI) ---
            
            # Lấy thời gian hiện tại theo múi giờ địa phương
            now_local = datetime.now(local_tz)
            
            # 1. Xác định tên file log cho ngày hôm nay
            today_str = now_local.strftime('%Y-%m-%d')
            output_dir = os.path.dirname(ALERT_OUTPUT_PATH)
            base_filename = os.path.basename(ALERT_OUTPUT_PATH).rsplit('.', 1)[0]
            daily_log_path = os.path.join(output_dir, f"{base_filename}-{today_str}.jsonl")
            
            if not os.path.exists(output_dir):
                os.makedirs(output_dir)

            # --- THAY ĐỔI 2: Logic xác định khoảng thời gian truy vấn ---
            # Nếu là ngày mới (tên file thay đổi) hoặc là lần chạy đầu tiên
            if daily_log_path != current_daily_log_path:
                logging.info(f"New day detected or first run. Setting log file to: {daily_log_path}")
                current_daily_log_path = daily_log_path
                # Reset, lấy từ đầu ngày hôm nay
                start_of_day_local = now_local.replace(hour=0, minute=0, second=0, microsecond=0)
                start_time_iso = start_of_day_local.isoformat()
                last_timestamp_processed = start_time_iso # Cập nhật mốc thời gian
            else:
                # Nếu vẫn trong ngày, lấy các alert mới hơn mốc thời gian đã lưu
                start_time_iso = last_timestamp_processed

            # Thời gian kết thúc luôn là hiện tại
            end_time_iso = now_local.isoformat()
            
            logging.info(f"Checking for new alerts from {start_time_iso} to {end_time_iso}")
            
            # 3. Lấy các cảnh báo mới
            # Hàm retrieve_alerts sử dụng 'gte' (lớn hơn hoặc bằng), nên có thể sẽ lấy lại alert cuối cùng của lần trước.
            # Điều này không sao, chúng ta sẽ xử lý ở bước sau.
            new_alerts_df = retrieve_alerts(es, ALERT_SEVERITY, start_time=start_time_iso, end_time=end_time_iso)

            if new_alerts_df is not None:
                # Bỏ qua alert đầu tiên nếu nó trùng với alert cuối cùng của lần trước
                if not new_alerts_df.empty and new_alerts_df.iloc[0]['@timestamp'] == last_timestamp_processed:
                    new_alerts_df = new_alerts_df.iloc[1:]

                if not new_alerts_df.empty:
                    logging.info(f"Found {len(new_alerts_df)} new alerts. Appending to file: {current_daily_log_path}")
                    
                    try:
                        # --- THAY ĐỔI 3: Mở file ở chế độ 'a' (append) ---
                        jsonl_output = new_alerts_df.to_json(orient='records', lines=True, force_ascii=False)
                        with open(current_daily_log_path, 'a', encoding='utf-8') as f:
                            f.write(jsonl_output + '\n') # Thêm ký tự xuống dòng để các lần ghi sau không dính liền
                        
                        # --- THAY ĐỔI 4: Cập nhật lại mốc thời gian cuối cùng ---
                        last_timestamp_processed = new_alerts_df.iloc[-1]['@timestamp']
                        logging.info(f"Updated last processed timestamp to: {last_timestamp_processed}")

                    except Exception as e:
                        logging.error(f"Failed to append alerts to {current_daily_log_path}: {e}")
                else:
                    logging.info("No new alerts found.")
            else:
                logging.warning("Failed to retrieve alerts from Elasticsearch.")
            
            time.sleep(POLL_INTERVAL)

    except KeyboardInterrupt:
        logging.info("Script stopped by user.")
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}", exc_info=True)
    finally:
        logging.info("Shutting down.")