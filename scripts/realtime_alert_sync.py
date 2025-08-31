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


from config import (
    REMOTE_USERNAME,
    REMOTE_HOST,
    SSH_TUNNEL_REMOTE_PORT,
    SSH_TUNNEL_LOCAL_PORT,
    ELASTIC_USER,
    ELASTIC_PASS,
    ELASTIC_HOST,
    ALERT_SEVERITY,
    ALERT_OUTPUT_PATH,
)

# --- CẤU HÌNH VÀ CÁC HÀM CỐ ĐỊNH ---

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

POLL_INTERVAL = 5
STATE_FILE = "state.json"
LOCAL_TZ = pytz.timezone('Asia/Ho_Chi_Minh')
INDEXING_DELAY_BUFFER = timedelta(seconds=40)
LOOKBACK_WINDOW = timedelta(minutes=3) # <-- THÊM MỚI: Định nghĩa cửa sổ nhìn lại là 3 phút
UTC = pytz.utc

# (Các hàm không thay đổi giữ nguyên)
def start_ssh_tunnel():
    try:
        local_port = SSH_TUNNEL_LOCAL_PORT
        remote_port = SSH_TUNNEL_REMOTE_PORT
        ssh_target = f"{REMOTE_USERNAME}@{REMOTE_HOST}"
        tunnel_process = subprocess.Popen(['ssh', '-N', '-L', f'{local_port}:localhost:{remote_port}', ssh_target])
        time.sleep(5)
        logging.info("SSH tunnel established successfully.")
        return tunnel_process
    except Exception as e:
        logging.error(f"Error starting SSH tunnel: {e}")
        return None

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

        alerts_list = [d.to_dict() for d in search_context.scan()]
        if not alerts_list:
            return pd.DataFrame()

        flattened_alerts = []
        for alert in alerts_list:
            flat_alert = {
                '@timestamp': alert.get('@timestamp'),
                'source.ip': alert.get('source', {}).get('ip'),
                'source.port': alert.get('source', {}).get('port'),
                'destination.ip': alert.get('destination', {}).get('ip'),
                'destination.port': alert.get('destination', {}).get('port'),
                'rule.name': alert.get('rule', {}).get('name'),
                'original_alert': alert
            }
            flattened_alerts.append(flat_alert)

        return pd.DataFrame(flattened_alerts)

    except Exception as e:
        logging.error(f"Error retrieving and flattening alerts: {e}")
        return pd.DataFrame()

# --- CÁC HÀM XỬ LÝ DỮ LIỆU ĐƯỢC CẬP NHẬT ---

# TÁCH RIÊNG HÀM TẠO HASH ĐỂ TÁI SỬ DỤNG
# def generate_alert_hash(row):
#     """
#     Tạo hash cho một dòng alert (Series) dựa trên các cột định danh.
#     """
#     cols_for_uniqueness = [
#         '@timestamp', 'source.ip', 'source.port',
#         'destination.ip', 'destination.port', 'rule.name'
#     ]
#     # Chỉ lấy các cột tồn tại trong `row` để tránh lỗi
#     existing_cols = [col for col in cols_for_uniqueness if col in row.index]
#     unique_tuple = tuple(str(row[col]) for col in existing_cols)
#     return hashlib.sha256(str(unique_tuple).encode('utf-8')).hexdigest()
# FILE: collectors/main_script.py

# TÁCH RIÊNG HÀM TẠO HASH ĐỂ TÁI SỬ DỤNG
def generate_alert_hash(row):
    """
    Tạo hash cho một dòng alert (Series) dựa trên các cột định danh.
    Đã được cập nhật để chuẩn hóa kiểu dữ liệu, tránh lỗi hash không khớp.
    """
    cols_for_uniqueness = [
        '@timestamp', 'source.ip', 'source.port',
        'destination.ip', 'destination.port', 'rule.name'
    ]
    existing_cols = [col for col in cols_for_uniqueness if col in row.index]
    
    values = []
    for col in existing_cols:
        val = row[col]
        # Bỏ qua các giá trị rỗng để tránh lỗi
        if val is None or pd.isna(val):
            values.append('') # Dùng chuỗi rỗng thay thế
            continue

        # --- ĐÂY LÀ PHẦN SỬA LỖI QUAN TRỌNG ---
        # Chuẩn hóa các trường port về kiểu số nguyên trước khi chuyển thành chuỗi.
        # Điều này đảm bảo str(54066) và str(54066.0) đều cho ra kết quả nhất quán.
        if col.endswith('.port'):
            try:
                # Dùng float() trước để xử lý cả '54066' và '54066.0'
                values.append(str(int(float(val))))
            except (ValueError, TypeError):
                values.append(str(val)) # Nếu không phải số thì giữ nguyên
        else:
            values.append(str(val))
            
    unique_tuple = tuple(values)
    return hashlib.sha256(str(unique_tuple).encode('utf-8')).hexdigest()

def deduplicate_alerts(df):
    """
    Loại bỏ các alert trùng lặp trong một DataFrame (một mẻ lấy về).
    """
    if df.empty:
        return df
    
    df['alert_hash'] = df.apply(generate_alert_hash, axis=1)
    deduplicated_df = df.drop_duplicates(subset='alert_hash', keep='first')
    return deduplicated_df.drop(columns=['alert_hash'])

# HÀM MỚI: LỌC CÁC ALERT ĐÃ TỒN TẠI TRONG FILE LOG
def filter_against_log(new_alerts_df, log_file_path):
    """
    Lọc DataFrame alert mới, loại bỏ những alert đã tồn tại trong file log.
    """
    if new_alerts_df.empty:
        return new_alerts_df
        
    try:
        if not os.path.exists(log_file_path) or os.path.getsize(log_file_path) == 0:
            # Nếu file log không tồn tại hoặc rỗng, không cần lọc
            return new_alerts_df

        # Đọc file log hiện tại
        existing_alerts_df = pd.read_json(log_file_path, lines=True)
        if existing_alerts_df.empty:
            return new_alerts_df

        # Tạo hash cho các alert đã có trong log
        existing_hashes = set(existing_alerts_df.apply(generate_alert_hash, axis=1))
        
        # Tạo hash cho các alert mới
        new_alerts_df['alert_hash'] = new_alerts_df.apply(generate_alert_hash, axis=1)

        # Lọc ra những alert có hash CHƯA xuất hiện trong log
        truly_new_alerts_df = new_alerts_df[~new_alerts_df['alert_hash'].isin(existing_hashes)]

        return truly_new_alerts_df.drop(columns=['alert_hash'])

    except Exception as e:
        logging.error(f"Error filtering against log file {log_file_path}: {e}")
        # Trong trường hợp lỗi, trả về DataFrame gốc để tránh mất dữ liệu
        return new_alerts_df

# ----- CÁC HÀM XỬ LÝ THỜI GIAN ĐƯỢC CHUẨN HÓA VỀ UTC -----

def save_last_timestamp(ts_obj):
    try:
        ts_utc_obj = ts_obj.astimezone(UTC)
        with open(STATE_FILE, 'w') as f:
            json.dump({'last_timestamp': ts_utc_obj.isoformat()}, f)
    except Exception as e:
        logging.error(f"Could not save state to {STATE_FILE}: {e}")

def load_last_timestamp():
    try:
        with open(STATE_FILE, 'r') as f:
            data = json.load(f)
            last_ts_str = data.get('last_timestamp')
            if last_ts_str:
                ts_obj = parser.parse(last_ts_str)
                ts_utc_obj = ts_obj.astimezone(UTC)
                logging.info(f"Loaded state. Resuming from {ts_utc_obj.isoformat()}")
                return ts_utc_obj
    except Exception:
        logging.warning(f"State file not found or invalid. Starting from a recent past time.")
    
    return (datetime.now(LOCAL_TZ) - INDEXING_DELAY_BUFFER).astimezone(UTC)

# --- KHỐI THỰC THI CHÍNH - PHIÊN BẢN CẬP NHẬT ---
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

    last_ts_utc_obj = load_last_timestamp()

    logging.info(f"Starting real-time alert monitoring. All times are handled in UTC.")
    logging.info(f"Press Ctrl+C to stop.")

    try:
        while True:
            # --- Xác định các khoảng thời gian ---
            # 1. Khoảng thời gian chính (tiến tới)
            start_time_main_utc_obj = last_ts_utc_obj
            end_time_utc_obj = (datetime.now(LOCAL_TZ) - INDEXING_DELAY_BUFFER).astimezone(UTC)

            # 2. Khoảng thời gian nhìn lại (look-back)
            start_time_lookback_utc_obj = end_time_utc_obj - LOOKBACK_WINDOW
            
            if start_time_main_utc_obj >= end_time_utc_obj:
                logging.warning(f"Time window invalid (start >= end): {start_time_main_utc_obj.isoformat()} >= {end_time_utc_obj.isoformat()}. Skipping.")
                time.sleep(POLL_INTERVAL)
                continue

            # --- Thực hiện 2 truy vấn ---
            # Truy vấn chính
            start_time_main_str = start_time_main_utc_obj.isoformat()
            end_time_main_str = end_time_utc_obj.isoformat()
            logging.info(f"🪟  CHECKIN MAIN window from {start_time_main_str} to {end_time_main_str}")
            main_alerts_df = retrieve_alerts(es, ALERT_SEVERITY, start_time_main_str, end_time_main_str)
            
            # Truy vấn look-back
            start_time_lookback_str = start_time_lookback_utc_obj.isoformat()
            end_time_lookback_str = end_time_utc_obj.isoformat()
            logging.info(f"📚 CHECKING LOOKBACK window from {start_time_lookback_str} to {end_time_lookback_str}")
            lookback_alerts_df = retrieve_alerts(es, ALERT_SEVERITY, start_time_lookback_str, end_time_lookback_str)
            
            # --- Gộp và xử lý dữ liệu ---
            combined_alerts_df = pd.concat([main_alerts_df, lookback_alerts_df], ignore_index=True)
            
            # Khử trùng lặp trong mẻ dữ liệu vừa lấy về
            unique_batch_df = deduplicate_alerts(combined_alerts_df)
            
            # Xác định file log của ngày hôm nay
            today_str = datetime.now(LOCAL_TZ).strftime('%Y-%m-%d')
            output_dir = os.path.dirname(ALERT_OUTPUT_PATH)
            base_filename = os.path.basename(ALERT_OUTPUT_PATH).rsplit('.', 1)[0]
            daily_log_path = os.path.join(output_dir, f"{base_filename}-{today_str}.jsonl")
            if not os.path.exists(output_dir): os.makedirs(output_dir)
            if not os.path.exists(daily_log_path):
                open(daily_log_path, 'a').close()
                logging.info(f"Created empty log file for today: {daily_log_path}")

            # Lọc lại với các alert đã có trong file log để chỉ lấy ra những alert thực sự mới
            truly_new_alerts_df = filter_against_log(unique_batch_df, daily_log_path)
            
            if not truly_new_alerts_df.empty:
                truly_new_alerts_df = truly_new_alerts_df.sort_values(by='@timestamp').reset_index(drop=True)
                logging.info(f"--------------------------------------------------------------------")
                logging.info(f" ✅ Found {len(truly_new_alerts_df)} TRULY new alerts. Appending to log.")
                logging.info(f"--------------------------------------------------------------------")
                jsonl_output = truly_new_alerts_df.to_json(orient='records', lines=True, force_ascii=False)
                with open(daily_log_path, 'a', encoding='utf-8') as f:
                    # Ghi từng dòng để tránh lỗi nếu có alert không hợp lệ
                    for line in jsonl_output.strip().split('\n'):
                        f.write(line + '\n')

                # Cập nhật last_timestamp dựa trên alert mới nhất đã được ghi
                last_alert_ts_str = truly_new_alerts_df.iloc[-1]['@timestamp']
                last_ts_utc_obj = parser.parse(last_alert_ts_str).astimezone(UTC) + timedelta(milliseconds=1)
            else:
                logging.info("❌ No new alerts found in this interval.")
                # Nếu không có alert mới, last_ts vẫn tiến tới end_time của chu kỳ này
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