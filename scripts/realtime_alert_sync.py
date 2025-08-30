from config import *
from elasticsearch import Elasticsearch
from elasticsearch_dsl import Search
from datetime import datetime, timezone, timedelta
import urllib3
import subprocess
import time
import json
import logging
import os
import hashlib
import pandas as pd
import pytz
from dateutil import parser

# --- CẤU HÌNH VÀ CÁC HÀM CỐ ĐỊNH ---

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

POLL_INTERVAL = 5
STATE_FILE = "state.json"
LOCAL_TZ = pytz.timezone('Asia/Ho_Chi_Minh')
INDEXING_DELAY_BUFFER = timedelta(seconds=65)
UTC = pytz.utc # Định nghĩa múi giờ UTC để sử dụng

# (Các hàm không thay đổi giữ nguyên)
def start_ssh_tunnel():
    try:
        local_port = ssh_tunnel_local_port
        remote_port = ssh_tunnel_remote_port
        ssh_target = f"{remote_username}@{remote_host}"
        tunnel_process = subprocess.Popen(['ssh', '-N', '-L', f'{local_port}:localhost:{remote_port}', ssh_target])
        time.sleep(5)
        logging.info("SSH tunnel established successfully.")
        return tunnel_process
    except Exception as e:
        logging.error(f"Error starting SSH tunnel: {e}")
        return None

def connect_elasticsearch():
    try:
        es = Elasticsearch([elastic_host], ca_certs=False, verify_certs=False, basic_auth=(elastic_user, elastic_pass))
        if es.ping():
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            logging.info("Connected to Elasticsearch.")
            return es
        return None
    except Exception as e:
        logging.error(f"Elasticsearch connection error: {e}")
        return None

def retrieve_alerts(es, severity_list, start_time_str, end_time_str):
    """
    Truy vấn và "làm phẳng" dữ liệu alert để các cột lồng nhau 
    (như source.ip, rule.name) được đưa lên cấp cao nhất.
    """
    try:
        from elasticsearch_dsl import Q

        severity_query = Q('bool', 
            should=[
                Q('terms', **{'rule.severity': severity_list}),
                Q('terms', **{'event.severity': severity_list})
            ],
            minimum_should_match=1
        )

        search_context = Search(using=es, index='*logs-*') \
            .query("query_string", query="event.module:suricata") \
            .query(severity_query) \
            .filter('range', **{'@timestamp': {'gte': start_time_str, 'lte': end_time_str}}) \
            .sort('@timestamp')

        # Bước 1: Lấy dữ liệu thô
        alerts_list = [d.to_dict() for d in search_context.scan()]
        if not alerts_list:
            return pd.DataFrame()

        # Bước 2: "Làm phẳng" dữ liệu
        flattened_alerts = []
        for alert in alerts_list:
            flat_alert = {
                '@timestamp': alert.get('@timestamp'),
                'source.ip': alert.get('source', {}).get('ip'),
                'source.port': alert.get('source', {}).get('port'),
                'destination.ip': alert.get('destination', {}).get('ip'),
                'destination.port': alert.get('destination', {}).get('port'),
                'rule.name': alert.get('rule', {}).get('name'),
                # Giữ lại toàn bộ alert gốc để các hàm khác có thể dùng
                'original_alert': alert 
            }
            flattened_alerts.append(flat_alert)

        # Bước 3: Tạo DataFrame từ dữ liệu đã được làm phẳng
        return pd.DataFrame(flattened_alerts)
        
    except Exception as e:
        logging.error(f"Error retrieving and flattening alerts: {e}")
        return pd.DataFrame()

# HÀM DEDUPLICATE PHIÊN BẢN HOÀN THIỆN
def deduplicate_alerts(df):
    """
    Tạo hash để loại bỏ các alert trùng lặp.
    Sử dụng tuple để tạo hash nhằm đảm bảo tính duy nhất và chính xác.
    """
    if df.empty:
        return df
        
    # Các cột quan trọng nhất để xác định một alert là duy nhất
    # Dù thời gian, IP, port giống nhau, nhưng nếu rule.name khác nhau, đó là alert khác nhau.
    cols_for_uniqueness = [
        '@timestamp', 
        'source.ip', 
        'source.port', 
        'destination.ip', 
        'destination.port', 
        'rule.name'
    ]
    
    # Lấy các cột thực sự tồn tại trong DataFrame
    existing_cols = [col for col in cols_for_uniqueness if col in df.columns]
    logging.info(f"Deduplicating alerts based on columns: {existing_cols}")

    def create_hash(row):
        # Tạo một tuple từ các giá trị của hàng
        # Chuyển các giá trị thành string để đảm bảo hash được
        unique_tuple = tuple(str(row[col]) for col in existing_cols)
        # Hash tuple đó
        return hashlib.sha256(str(unique_tuple).encode('utf-8')).hexdigest()

    # Áp dụng hàm create_hash cho mỗi hàng để tạo cột 'alert_hash'
    df['alert_hash'] = df.apply(create_hash, axis=1)
    
    # Loại bỏ các dòng có hash trùng lặp, chỉ giữ lại dòng đầu tiên
    deduplicated_df = df.drop_duplicates(subset='alert_hash', keep='first')
    
    return deduplicated_df.drop(columns=['alert_hash'])

# ----- CÁC HÀM XỬ LÝ THỜI GIAN ĐƯỢC CHUẨN HÓA VỀ UTC -----

def save_last_timestamp(ts_obj):
    """Lưu đối tượng datetime vào file state dưới dạng string ISO UTC."""
    try:
        # Đảm bảo đối tượng luôn được chuyển về UTC trước khi lưu
        ts_utc_obj = ts_obj.astimezone(UTC)
        with open(STATE_FILE, 'w') as f:
            json.dump({'last_timestamp': ts_utc_obj.isoformat()}, f)
    except Exception as e:
        logging.error(f"Could not save state to {STATE_FILE}: {e}")

def load_last_timestamp():
    """Tải timestamp từ file và trả về một đối tượng datetime đã được chuẩn hóa sang UTC."""
    try:
        with open(STATE_FILE, 'r') as f:
            data = json.load(f)
            last_ts_str = data.get('last_timestamp')
            if last_ts_str:
                ts_obj = parser.parse(last_ts_str)
                ts_utc_obj = ts_obj.astimezone(UTC) # Chuyển về UTC
                logging.info(f"Loaded state. Resuming from {ts_utc_obj.isoformat()}")
                return ts_utc_obj
    except Exception:
        logging.warning(f"State file not found or invalid. Starting from a recent past time.")
    
    # Nếu có lỗi, lấy giờ địa phương và ngay lập tức chuyển về UTC
    return (datetime.now(LOCAL_TZ) - INDEXING_DELAY_BUFFER).astimezone(UTC)

# --- KHỐI THỰC THI CHÍNH - PHIÊN BẢN CHUẨN UTC ---
if __name__ == "__main__":
    
    try:
        if os.path.exists(STATE_FILE):
            os.remove(STATE_FILE)
            logging.info(f"Removed old state file: {STATE_FILE}")
    except Exception as e:
        logging.error(f"Error removing state file {STATE_FILE}: {e}")
        
        
    tunnel_proc = start_ssh_tunnel()
    if not tunnel_proc: exit()

    es = connect_elasticsearch()
    if not es:
        tunnel_proc.terminate()
        exit()

    # last_ts_utc_obj luôn là đối tượng datetime ở múi giờ UTC
    last_ts_utc_obj = load_last_timestamp()

    logging.info(f"Starting real-time alert monitoring. All times are handled in UTC.")
    logging.info(f"Press Ctrl+C to stop.")

    try:
        while True:
            start_time_utc_obj = last_ts_utc_obj
            # Lấy giờ địa phương và ngay lập tức chuyển về UTC để so sánh
            end_time_utc_obj = (datetime.now(LOCAL_TZ) - INDEXING_DELAY_BUFFER).astimezone(UTC)

            if start_time_utc_obj >= end_time_utc_obj:
                logging.warning(f"Time window invalid (start >= end): {start_time_utc_obj.isoformat()} >= {end_time_utc_obj.isoformat()}. Skipping.")
                time.sleep(POLL_INTERVAL)
                continue

            start_time_str = start_time_utc_obj.isoformat()
            end_time_str = end_time_utc_obj.isoformat()

            logging.info(f"Checking for new alerts from {start_time_str} to {end_time_str}")
            new_alerts_df = retrieve_alerts(es, alert_severity, start_time_str, end_time_str)
            unique_alerts_df = deduplicate_alerts(new_alerts_df)

            if not unique_alerts_df.empty:
                unique_alerts_df = unique_alerts_df.sort_values(by='@timestamp').reset_index(drop=True)
                logging.info(f"Found {len(unique_alerts_df)} new unique alerts. Appending to log.")

                today_str = datetime.now(LOCAL_TZ).strftime('%Y-%m-%d')
                output_dir = os.path.dirname(alert_output_path)
                base_filename = os.path.basename(alert_output_path).rsplit('.', 1)[0]
                daily_log_path = os.path.join(output_dir, f"{base_filename}-{today_str}.jsonl")
                if not os.path.exists(output_dir): os.makedirs(output_dir)
                
                jsonl_output = unique_alerts_df.to_json(orient='records', lines=True, force_ascii=False)
                with open(daily_log_path, 'a', encoding='utf-8') as f:
                    f.write(jsonl_output + '\n')

                last_alert_ts_str = unique_alerts_df.iloc[-1]['@timestamp']
                last_ts_utc_obj = parser.parse(last_alert_ts_str).astimezone(UTC) + timedelta(milliseconds=1)
            else:
                logging.info("No new alerts found in this interval.")
                last_ts_utc_obj = end_time_utc_obj

            save_last_timestamp(last_ts_utc_obj)
            time.sleep(POLL_INTERVAL)

    except KeyboardInterrupt:
        logging.info("Script stopped by user (Ctrl+C).")
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}", exc_info=True)
    finally:
        logging.info("Shutting down.")
        if tunnel_proc:
            tunnel_proc.terminate()