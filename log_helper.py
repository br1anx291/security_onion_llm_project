# security_onion_llm_project/log_helper.py

import os
import logging
import re
from datetime import datetime, time, timezone

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

def find_log_files(base_dir: str, log_type: str, alert_timestamp: float) -> list[str]:
    """
    Finds all potentially relevant log files for a specific log type and time.
    This function searches in both historical log directories (by date/time) and the 'current' directory,
    and then returns a combined list of the found files.
    """
    found_files = []
    
    try:
        dt_object = datetime.fromtimestamp(alert_timestamp, tz=timezone.utc)
        alert_time = dt_object.time().replace(microsecond=0)
    except (TypeError, ValueError) as e:
        logging.error(f"Invalid timestamp: {alert_timestamp}. Error: {e}")
        return []

    # === PART 1: SEARCH IN HISTORICAL LOGS (DATE-BASED DIRECTORIES) ===
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
                        logging.info(f"Found historical log file: {full_path}")
                        found_files.append(full_path)
                        # Only one historical file should match at a time, so we stop searching here.
                        break
                except ValueError:
                    continue
        except FileNotFoundError:
            pass # Directory might exist but be unreadable.
    else:
        logging.warning(f"Historical log directory for date {date_folder_name} not found.")

    # === PART 2: ALWAYS SEARCH IN THE 'CURRENT' DIRECTORY ===
    current_log_dir = os.path.join(base_dir, "current")
    if os.path.isdir(current_log_dir):
        try:
            for filename in os.listdir(current_log_dir):
                # Find files like http.log, dns.log, etc.
                if filename.startswith(f"{log_type}.") and filename.endswith(".log"):
                    full_path = os.path.join(current_log_dir, filename)
                    logging.info(f"Found 'current' log file: {full_path}")
                    found_files.append(full_path)
        except OSError as e:
            logging.error(f"Error accessing 'current' directory: {e}")
            
    # === PART 3: RETURN COMBINED RESULTS ===
    if not found_files:
        logging.warning(f"No log files found for '{log_type}' at time {alert_time} in either historical or 'current' directories.")
    
    # Use a set to ensure there are no duplicate file paths.
    return sorted(list(set(found_files)))