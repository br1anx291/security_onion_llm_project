import os
import logging
import getpass
import paramiko
import re
import subprocess
import gzip
from concurrent.futures import ThreadPoolExecutor, as_completed
# Thay đổi import để lấy config từ thư mục hiện tại
from config import remote_host, remote_username, remote_zeek_log_path, local_zeek_log_path, local_zeek_zip_path, local_zeek_unzip_path,remote_zeek_spool_path

# Các hàm setup logging, create_ssh_sftp, download_file, list_zeek_log_folders giữ nguyên
# setup logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

def create_ssh_sftp():
    try:
        ssh_target = f"{remote_username}@{remote_host}"
        logging.info(f"Establishing SSH + SFTP session to {ssh_target}...")
        password = getpass.getpass(prompt=f"Enter password for {ssh_target}: ")

        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(remote_host, username=remote_username, password=password)
        sftp = ssh.open_sftp()

        logging.info("SSH + SFTP session established successfully.")
        return ssh, sftp
    except Exception as e:
        logging.error(f"Failed to establish SSH/SFTP session: {e}")
        return None, None

# Hàm tải file 
def download_file(sftp, remote_path, local_path):
    try:
        # logging.info(f"📥 Starting download: {remote_path}")
        sftp.get(remote_path, local_path)
        # logging.info(f"Downloaded: {os.path.basename(local_path)} to {os.path.dirname(local_path)}")
    except Exception as e:
        logging.warning(f"Failed to download {os.path.basename(remote_path)}: {e}")

# Hàm liệt kê các ngày trong folder Zeek
def list_zeek_log_folders(sftp, remote_root):
    try:
        folders = sftp.listdir(remote_root)
        return [f for f in folders if re.match(r"\d{4}-\d{2}-\d{2}", f)]
    except Exception as e:
        logging.error(f"Failed to list Zeek root folder: {e}")
        return []

# Hàm kéo Zeek logs từ các ngày
def fetch_logs_from_folder(folder_name, ssh, sftp):
    logging.info(f"🔍 Fetching logs from entry: {folder_name}...")
    
    local_folder_path = os.path.join(local_zeek_zip_path, folder_name)
    os.makedirs(local_folder_path, exist_ok=True)
    
    remote_folder_path = f"{remote_zeek_log_path}/{folder_name}/"
    files_to_check_suffix = ".log.gz"
    downloaded_files = []
    # =========================================================

    try:
        file_list = sftp.listdir(remote_folder_path)
        files_to_download = [f for f in file_list if f.endswith(files_to_check_suffix)]

        if not files_to_download:
            logging.info(f"No target files ('{files_to_check_suffix}') found in '{remote_folder_path}'.")
            return

        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = {}
            for file in files_to_download:
                remote_file = os.path.join(remote_folder_path, file)
                local_file = os.path.join(local_folder_path, file)
                
                try:
                    remote_file_size = sftp.stat(remote_file).st_size
                    if os.path.exists(local_file) and os.path.getsize(local_file) == remote_file_size:
                        # logging.info(f"✅ Skipping unchanged file: {file} in {folder_name}")
                        continue
                except Exception as e:
                    logging.warning(f"⚠️ Failed to stat file {file}: {e}")
                
                logging.debug(f"📥 Queueing download: {file}")
                futures[executor.submit(download_file, sftp, remote_file, local_file)] = file
                downloaded_files.append(file)
            
                logging.debug(f"⏳ Waiting on download threads...")
                for future in as_completed(futures):
                    logging.debug("🔄 One download thread finished.")
                    future.result()

    except Exception as e:
        logging.error(f"❌ Cannot access remote folder {remote_folder_path}: {e}")
        
    return downloaded_files


def fetch_logs_from_current(ssh=None, sftp=None):
    """
    Đồng bộ tất cả các file .log từ spool (/nsm/zeek/spool/logger/)
    về thư mục local, chỉ lấy file .log bằng rsync.
    """
    local_current_path = os.path.join(local_zeek_unzip_path, "current")
    os.makedirs(local_current_path, exist_ok=True)
    remote_spool_path = remote_zeek_spool_path.rstrip("/") + "/"

    logging.info(f"🔄 Syncing *.log files from {remote_host}:{remote_spool_path} ...")

    try:
        rsync_cmd = [
            "rsync", "-avz", "--progress",
            "--include", "*.log",
            "--exclude", "*",
            "-e", "ssh",
            f"{remote_username}@{remote_host}:{remote_spool_path}",
            local_current_path
        ]

        result = subprocess.run(rsync_cmd, capture_output=True, text=True)

        if result.returncode != 0:
            logging.error(f"❌ rsync failed:\n{result.stderr}")
        else:
            # 🧠 Tách các dòng báo file được tải (lọc dòng thông tin của rsync)
            files_downloaded = [
                line.strip() for line in result.stdout.splitlines()
                if line.strip() and not line.startswith("sending") and not line.startswith("sent")
            ]

            logging.info(f"✅ rsync completed successfully.")
            logging.info(f"📦 Total files synced: {len(files_downloaded)}")
            logging.debug("🔍 Full rsync output:")
            logging.debug(result.stdout)

    except Exception as e:
        logging.error(f"❌ Exception during rsync: {e}")
        
        
def decompress_logs_only(date_str, downloaded_files):
    # Đường dẫn đến thư mục chứa .gz theo ngày
    gz_folder = os.path.join(local_zeek_zip_path, date_str)

    # Đường dẫn đến thư mục chứa .log sau giải nén theo ngày
    log_folder = os.path.join(local_zeek_unzip_path, date_str)
    os.makedirs(log_folder, exist_ok=True)

    for filename in downloaded_files:
        if not filename.endswith(".log.gz"):
            logging.warning(f"⚠️ Skipping non-log file: {filename}")
            continue

        gz_path = os.path.join(gz_folder, filename)
        log_filename = filename[:-3]  # remove ".gz"
        log_path = os.path.join(log_folder, log_filename)

        try:
            with gzip.open(gz_path, 'rt', encoding='utf-8') as f_in, open(log_path, 'w', encoding='utf-8') as f_out:
                f_out.write(f_in.read())
            # logging.info(f"🗜️ Decompressed: {filename} → {log_filename}")
        except Exception as e:
            logging.error(f"❌ Failed to decompress {filename}: {e}")

# Hàm main giữ nguyên
if __name__ == "__main__":
    ssh, sftp = create_ssh_sftp()
    if not sftp:
        logging.error("Exiting: Could not establish SFTP session.")
        exit(1)
        
    os.makedirs(local_zeek_log_path, exist_ok=True)

    folders_to_check = list_zeek_log_folders(sftp, remote_zeek_log_path)
    logging.info(f"Entries to check in '{remote_zeek_log_path}': {folders_to_check}")
    for folder_name in folders_to_check:
        downloaded_files = fetch_logs_from_folder(folder_name, ssh, sftp)
        if downloaded_files:
            decompress_logs_only(folder_name, downloaded_files)
        else:
            logging.info(f"🚫 No new files downloaded for {folder_name}, skipping decompress and convert.")


    logging.info("+++++++++++++++++++++++++++++++++++++")
    file_list = sftp.listdir(remote_zeek_spool_path)
    logging.info(f"Current Zeek log in spool: {file_list}")
    fetch_logs_from_current(ssh, sftp)

    sftp.close()
    ssh.close()
    logging.info("✅ Zeek log download pipeline completed.")