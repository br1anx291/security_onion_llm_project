# FILE: collectors/conn_collector.py

import subprocess
import json
import logging
from datetime import datetime

# Chúng ta cũng cần hàm find_log_files ở đây
from log_helper import find_log_files
from config import ZEEK_LOGS_DIR, CONN_LOG_TIME_WINDOW_SECONDS
class ConnCollector:
    """
    Một collector đặc biệt, có nhiệm vụ tìm kiếm bản ghi conn.log gốc
    tương ứng với một alert. Đây là bước đầu tiên của quá trình làm giàu.
    """
    def __init__(self, zeek_logs_dir: str, time_window_seconds: int):
        """
        Hàm khởi tạo.
        
        Args:
            zeek_logs_dir (str): Đường dẫn tới thư mục chứa log Zeek.
            time_window_seconds (int): Cửa sổ thời gian (giây) để tìm kiếm.
        """
        self.zeek_logs_dir = ZEEK_LOGS_DIR
        self.time_window_seconds = CONN_LOG_TIME_WINDOW_SECONDS
        logging.info("ConnCollector initialized.")

    def _extract_timestamp_from_alert(self, alert: dict) -> float | None:
        """
        Trích xuất và chuyển đổi timestamp từ một alert.
        Hàm này xử lý trường hợp timestamp nằm trong một chuỗi JSON lồng nhau.
        """
        try:
            # 1. Parse chuỗi JSON trong trường 'message'
            message_data = json.loads(alert['message'])
            
            # 2. Lấy chuỗi timestamp thô
            ts_str_raw = message_data['timestamp']
            
            # 3. Chuẩn hóa chuỗi (xử lý cả '+0000' và 'Z')
            if ts_str_raw.endswith('+0000'):
                ts_str_normalized = ts_str_raw[:-2] + ':' + ts_str_raw[-2:]
            else:
                ts_str_normalized = ts_str_raw.replace('Z', '+00:00')
                
            # 4. Chuyển đổi thành Unix timestamp và trả về
            timestamp = datetime.fromisoformat(ts_str_normalized).timestamp()
            return timestamp

        except (KeyError, TypeError, json.JSONDecodeError, ValueError) as e:
            # Bẫy tất cả các lỗi có thể xảy ra: thiếu key, sai kiểu, JSON lỗi, format lỗi
            logging.error(f"Could not extract timestamp from alert. Error: {e}")
            return None

    def find_connection(self, alert: dict) -> tuple[str | None, dict | None]:
        timestamp = self._extract_timestamp_from_alert(alert)
        if timestamp is None:
            return None, None

        conn_log_files = find_log_files(ZEEK_LOGS_DIR, "conn", timestamp)
        if not conn_log_files:
            logging.warning(f"No conn.*.log files found for timestamp {timestamp}.")
            return None, None

        community_id = alert.get("network", {}).get("community_id")

        # --- Luồng 1: Thử tìm bằng Community ID (Rất nhanh) ---
        """
        Tìm UID và tóm tắt kết nối.
        PHIÊN BẢN NÂNG CẤP:
        1. Lọc chặt chẽ các ứng viên theo cửa sổ thời gian để tránh Community ID collision.
        2. Ưu tiên chọn ứng viên có DURATION lớn nhất trong cửa sổ đó.
        """
        timestamp = self._extract_timestamp_from_alert(alert)
        if timestamp is None:
            return None, None

        conn_log_files = find_log_files(ZEEK_LOGS_DIR, "conn", timestamp)
        if not conn_log_files:
            logging.warning(f"No conn.*.log files found for timestamp {timestamp}.")
            return None, None

        # --- Giai đoạn 1: Thu thập tất cả ứng viên thô ---
        all_raw_lines = []
        community_id = alert.get("network", {}).get("community_id")

        if community_id:
            logging.info(f"Attempting to find connection using Community ID: {community_id}")
            command = "grep"
            for log_file in conn_log_files:
                try:
                    result = subprocess.run(
                        [command, f'"community_id":"{community_id}"', log_file],
                        capture_output=True, text=True, check=False
                    )
                    if result.returncode <= 1 and result.stdout:
                        all_raw_lines.extend(result.stdout.strip().split('\n'))
                except Exception as e:
                    logging.warning(f"Error while searching by community_id in {log_file}: {e}")
            
            if not all_raw_lines:
                 logging.warning(f"Community ID {community_id} provided, but no matching logs found.")

        # --- Luồng 2: Dự phòng, tìm bằng 5-Tuple (Chậm hơn) ---

        # === BẮT ĐẦU LOGIC FALLBACK 5-TUPLE ===
        # Chỉ chạy nếu việc tìm bằng Community ID không có kết quả
        if not all_raw_lines:
            logging.warning("Community ID search failed or not available. Falling back to 5-tuple search.")
            try:
                src_ip = alert['source']['ip']
                src_port = alert['source']['port']
                dest_ip = alert['destination']['ip']
                dest_port = alert['destination']['port']
            except (KeyError, TypeError):
                logging.error("Alert is missing source/destination IP/port for 5-tuple search.")
                return None, None
            
            command = "grep"
            for log_file in conn_log_files:
                try:
                    # Dùng chuỗi các lệnh grep để lọc hiệu quả
                    p1 = subprocess.Popen([command, f'"id.orig_h":"{src_ip}"', log_file], stdout=subprocess.PIPE, text=True)
                    p2 = subprocess.Popen([command, f'"id.orig_p":{src_port}'], stdin=p1.stdout, stdout=subprocess.PIPE, text=True)
                    p3 = subprocess.Popen([command, f'"id.resp_h":"{dest_ip}"'], stdin=p2.stdout, stdout=subprocess.PIPE, text=True)
                    p4 = subprocess.Popen([command, f'"id.resp_p":{dest_port}'], stdin=p3.stdout, stdout=subprocess.PIPE, text=True)
                    
                    # Đóng các pipe không cần thiết
                    p1.stdout.close()
                    p2.stdout.close()
                    p3.stdout.close()

                    result_stdout, _ = p4.communicate()
                    if result_stdout:
                        all_raw_lines.extend(result_stdout.strip().split('\n'))
                except Exception as e:
                    logging.warning(f"Error during 5-tuple search in {log_file}: {e}")
        # === KẾT THÚC LOGIC FALLBACK 5-TUPLE ===

        # --- Phần xử lý kết quả (Dùng chung cho cả 2 luồng) ---
        if not all_raw_lines:
            logging.warning("No raw connection logs found matching the criteria.")
            return None, None

        # --- Giai đoạn 2: Lọc ứng viên theo cửa sổ thời gian ---
        time_relevant_candidates = []
        for line in all_raw_lines:
            if not line: continue
            try:
                log_entry = json.loads(line)
                log_ts = float(log_entry['ts'])
                time_diff = abs(log_ts - timestamp)

                # **LOGIC LỌC QUAN TRỌNG NHẤT**
                # Chỉ giữ lại những ứng viên nằm trong cửa sổ thời gian hẹp
                if time_diff < CONN_LOG_TIME_WINDOW_SECONDS:
                    time_relevant_candidates.append(log_entry)

            except (json.JSONDecodeError, KeyError, TypeError, ValueError):
                # Bỏ qua các dòng log lỗi hoặc thiếu trường
                continue
        
        if not time_relevant_candidates:
            logging.warning(f"Found {len(all_raw_lines)} raw candidates, but NONE were within the time window of {CONN_LOG_TIME_WINDOW_SECONDS}s.")
            return None, None

        logging.info(f"Found {len(time_relevant_candidates)} time-relevant candidates. Selecting the best match...")

        # --- Giai đoạn 3: Chọn best_match từ các ứng viên hợp lệ ---
        best_match = None
        max_duration = -1.0  # Bắt đầu với duration âm để đảm bảo mọi duration > 0 sẽ được chọn

        for candidate in time_relevant_candidates:
            # Lấy duration, mặc định là 0 nếu không có
            duration = float(candidate.get('duration', 0.0) or 0.0)
            
            # **LOGIC CHỌN LỌC MỚI**
            # Ưu tiên ứng viên có DURATION dài nhất
            if duration > max_duration:
                max_duration = duration
                best_match = candidate
        
        # --- Giai đoạn 4: Trả về kết quả ---
        if best_match:
            uid = best_match.get('uid')
            # Lấy thông tin time_diff của chính best_match để log
            final_time_diff = abs(float(best_match.get('ts', 0.0)) - timestamp)
            
            conn_summary = {
                "uid": uid,
                "duration": best_match.get('duration'),
                "orig_bytes": best_match.get('orig_bytes'),
                "resp_bytes": best_match.get('resp_bytes'),
                "conn_state": best_match.get('conn_state'),
                "service": best_match.get('service'),
                "history": best_match.get('history'),
            }
            logging.info(f"Successfully selected best match UID: {uid} (duration: {max_duration:.6f}s, time_diff: {final_time_diff:.4f}s)")
            return uid, conn_summary
            
        logging.error("This should not happen: Found time-relevant candidates but failed to select a best match.")
        return None, None
    
