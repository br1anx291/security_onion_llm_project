# security_onion_llm_project/log_helper.py

import os
import logging
from datetime import datetime

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

def find_log_files(base_dir: str, log_type: str, timestamp: float) -> list[str]:
    """
    Tìm tất cả các file log cho một loại log và thời điểm cụ thể.
    Hàm này trả về một danh sách các đường dẫn file (string).
    """
    logging.debug(f"Searching for log_type='{log_type}' in base_dir='{base_dir}' for timestamp='{timestamp}'")
    
    def scan_directory(path_to_scan: str) -> list[str]:
        """Quét một thư mục và trả về danh sách các đường dẫn file khớp."""
        found_in_dir = []
        if not os.path.isdir(path_to_scan):
            logging.debug(f"Directory not found, skipping: {path_to_scan}")
            return []

        # logging.debug(f"Scanning directory: {path_to_scan}")
        prefix_to_match = f"{log_type}."
        
        for filename in os.listdir(path_to_scan):
            if filename.startswith(prefix_to_match) and filename.endswith(".log"):
                full_path = os.path.join(path_to_scan, filename)
                found_in_dir.append(full_path)
        
        logging.debug(f"Found {len(found_in_dir)} matching files in {path_to_scan}.")
        return found_in_dir

    try:
        dt_object = datetime.fromtimestamp(timestamp)
    except (TypeError, ValueError):
        logging.error(f"Invalid timestamp provided: {timestamp}")
        return []

    all_results = []
    
    date_folder_name = dt_object.strftime('%Y-%m-%d')
    path_for_date = os.path.join(base_dir, date_folder_name)
    all_results.extend(scan_directory(path_for_date))

    current_date_str = datetime.now().strftime('%Y-%m-%d')
    if date_folder_name == current_date_str:
        path_for_current = os.path.join(base_dir, 'current')
        all_results.extend(scan_directory(path_for_current))
    
    unique_results = sorted(list(set(all_results)))
    
    logging.info(f"Found a total of {len(unique_results)} files for log_type '{log_type}' on {date_folder_name}.")
    return unique_results
