import os
import time
import logging
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import paramiko

from config import (
    REMOTE_USERNAME,
    REMOTE_HOST,
    REMOTE_PORT,
    REMOTE_KEY_PATH,
)

# --- Đường dẫn file ---
# File JSONL ở máy local mà bạn muốn theo dõi
name_alert = f'alerts-{time.strftime("%Y-%m-%d")}'
LOCAL_FILE_PATH = f"../outputs/final_analysis/realtime/{name_alert}_analysis.jsonl" 
# File trên remote server mà bạn muốn ghi nối vào
REMOTE_FILE_PATH = "/opt/so/user_logs/llm_findings.jsonl"
# =========================================================

# Cấu hình logging
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S')

# Biến toàn cục để lưu vị trí đọc cuối cùng của file local
last_position = 0

def create_ssh_client():
    """Tạo và trả về một đối tượng SSH client đã kết nối."""
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        logging.info(f"Đang kết nối tới {REMOTE_USERNAME}@{REMOTE_HOST}...")
        
        if os.path.exists(REMOTE_KEY_PATH):
            client.connect(REMOTE_HOST, port=REMOTE_PORT, username=REMOTE_USERNAME, key_filename=REMOTE_KEY_PATH)
        else:
            logging.error(f"Lỗi: Không tìm thấy SSH key tại '{REMOTE_KEY_PATH}'.")
            return None

        logging.info("✅ Kết nối SSH thành công!")
        return client
    except Exception as e:
        logging.error(f"❌ Không thể kết nối SSH: {e}")
        return None

def append_to_remote_file(ssh_client, content):
    """Sử dụng SFTP để ghi nối nội dung vào file trên remote server một cách an toàn."""
    if not content:
        return

    logging.info(f"Sẵn sàng ghi nối {len(content.splitlines())} dòng mới vào remote file qua SFTP...")
    sftp = None
    remote_file = None
    try:
        # 1. Mở một phiên SFTP client từ SSH client đã có
        sftp = ssh_client.open_sftp()
        
        # 2. Mở file trên remote server với chế độ 'a' (append - ghi nối)
        # Nếu file chưa tồn tại, nó sẽ được tạo ra.
        remote_file = sftp.open(REMOTE_FILE_PATH, 'a')
        
        # 3. Ghi nội dung vào file
        remote_file.write(content)
        
        logging.info("✅ Ghi nối thành công qua SFTP!")
        
    except Exception as e:
        logging.error(f"❌ Đã xảy ra lỗi trong quá trình ghi file qua SFTP: {e}")
    finally:
        # 4. Đảm bảo đóng file và session SFTP để giải phóng tài nguyên
        if remote_file:
            remote_file.close()
        if sftp:
            sftp.close()

# *** LOGIC NÂNG CẤP NẰM Ở ĐÂY ***
def sync_content(ssh_client):
    """
    Đọc nội dung MỚI từ file local (dựa vào last_position) và gửi nó đi.
    Hàm này được dùng cho cả lần đồng bộ đầu tiên và các lần sau.
    """
    global last_position
    try:
        # Lấy kích thước file hiện tại
        current_size = os.path.getsize(LOCAL_FILE_PATH)
        # Nếu file bị thu nhỏ (ví dụ bị xóa trắng), reset lại từ đầu
        if current_size < last_position:
            logging.warning("File local dường như đã bị reset. Bắt đầu đọc lại từ đầu.")
            last_position = 0
            
        if current_size == last_position:
            return # Không có gì thay đổi

        with open(LOCAL_FILE_PATH, 'r', encoding='utf-8') as f:
            f.seek(last_position)
            new_content = f.read()
            # Cập nhật lại vị trí cuối cùng
            last_position = f.tell()

        if new_content:
            logging.info(f"Phát hiện {len(new_content)} bytes nội dung mới.")
            append_to_remote_file(ssh_client, new_content)
            
    except FileNotFoundError:
        logging.warning(f"File local '{LOCAL_FILE_PATH}' không tìm thấy. Bỏ qua chu kỳ sync.")
    except Exception as e:
        logging.error(f"Lỗi khi đọc file local: {e}")

class MyEventHandler(FileSystemEventHandler):
    """Bộ xử lý sự kiện: Gọi hàm sync_content khi file thay đổi."""
    def __init__(self, ssh_client):
        self.ssh_client = ssh_client

    def on_modified(self, event):
        if not event.is_directory and event.src_path == os.path.abspath(LOCAL_FILE_PATH):
            sync_content(self.ssh_client)

if __name__ == "__main__":
    if not os.path.exists(LOCAL_FILE_PATH):
        open(LOCAL_FILE_PATH, 'w').close()
        logging.info(f"File local '{LOCAL_FILE_PATH}' chưa tồn tại. Đã tạo file rỗng.")

    ssh = create_ssh_client()
    if not ssh:
        exit(1)

    # ======================== NÂNG CẤP QUAN TRỌNG ========================
    # 1. Đồng bộ toàn bộ nội dung file đã có ngay khi khởi động
    logging.info("Bắt đầu đồng bộ lần đầu (initial sync) toàn bộ file...")
    # `last_position` đang là 0, nên hàm này sẽ đọc từ đầu đến cuối file
    sync_content(ssh)
    logging.info("✅ Đồng bộ lần đầu hoàn tất.")
    # =====================================================================

    # 2. Sau đó, mới bắt đầu theo dõi thay đổi realtime
    path = os.path.dirname(os.path.abspath(LOCAL_FILE_PATH)) or '.'
    event_handler = MyEventHandler(ssh)
    observer = Observer()
    observer.schedule(event_handler, path, recursive=False)
    
    logging.info(f"🚀 Bắt đầu theo dõi thay đổi realtime cho file: {LOCAL_FILE_PATH}")
    observer.start()

    try:
        while True:
            # Vẫn giữ logic kiểm tra và kết nối lại SSH nếu bị mất
            if not ssh.get_transport() or not ssh.get_transport().is_active():
                logging.warning("Mất kết nối SSH. Đang thử kết nối lại...")
                ssh.close()
                ssh = create_ssh_client()
                if not ssh:
                    logging.error("Không thể kết nối lại. Script sẽ tạm dừng 5 giây.")
                    time.sleep(5)
                else:
                    event_handler.ssh_client = ssh # Cập nhật lại ssh client cho handler
            time.sleep(5)
    except KeyboardInterrupt:
        logging.info("🛑 Người dùng dừng chương trình.")
    finally:
        observer.stop()
        observer.join()
        if ssh:
            ssh.close()
            logging.info("Đã đóng kết nối SSH.")