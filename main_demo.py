# security_onion_llm_project/main_realtime.py


import json
import logging
from enrichment_manager import EnrichmentManager
from concurrent.futures import ThreadPoolExecutor, as_completed
from llm_client import LLMClient
import time
import os
from datetime import datetime
from typing import Iterator, Dict, Any
import threading
import pandas as pd
LOG_FORMAT = "%(asctime)s [%(threadName)-12.12s] [%(levelname)-5.5s]  %(message)s"
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)


TEST_MODE = False
# name_alert = f'alerts_all-{time.strftime("%Y-%m-%d")}'
# name_alert = 'alerts_all-2025-08-13'
name_alert = f'demo'

ALERTS_FILE_PATH = f"./so_alerts/{name_alert}.jsonl"
ENRICHED_PROMPTS_DIR = "./outputs/enriched_prompts/demo"
FINAL_ANALYSIS_OUTPUT_PATH = f"./outputs/final_analysis/demo/{name_alert}_analysis.jsonl"

MAX_WORKERS = 10
 
def get_next_alert_index(directory: str) -> int:
    """
    Quét một thư mục để tìm file enrichment có số index cao nhất và trả về số tiếp theo.
    Ví dụ: nếu tìm thấy 'alert_enrichment_5.json', hàm sẽ trả về 6.
    """
    if not os.path.isdir(directory):
        return 1 # Nếu thư mục không tồn tại, bắt đầu từ 1

    max_index = 0
    prefix = 'alert_enrichment_'
    suffix = '.jsonl' # Sửa thành .json cho nhất quán với json.dump(indent=4)

    for filename in os.listdir(directory):
        if filename.startswith(prefix) and filename.endswith(suffix):
            try:
                # Trích xuất số từ tên file, ví dụ: 'alert_enrichment_123.json' -> '123'
                num_str = filename[len(prefix):-len(suffix)]
                index = int(num_str)
                if index > max_index:
                    max_index = index
            except ValueError:
                # Bỏ qua các file không đúng định dạng
                continue
                
    # Số tiếp theo sẽ là số lớn nhất tìm được + 1
    return max_index + 1

## <<< THAY ĐỔI BẮT ĐẦU >>>
def process_and_write_alert(
    # manager: EnrichmentManager, llm_client: LLMClient, alert: dict, index: int, 
    # output_file_handle, lock: threading.Lock
        manager: EnrichmentManager, llm_client: LLMClient, alert_row: pd.Series, index: int, 
    output_file_handle, lock: threading.Lock
):
    """
    Hàm này giờ sẽ chịu trách nhiệm xử lý MỘT alert, ghi prompt ra file riêng,
    và ghi kết quả phân tích ra file output chính.
    Việc ghi file output chính được bảo vệ bởi Lock.
    """
    try:
        alert = alert_row['original_alert']
        logging.info(f"Worker #{index}: Bắt đầu xử lý alert...")
        
        # 1. Làm giàu Alert
        enriched_prompt_dict = manager.enrich_and_prompt(alert)
        if not enriched_prompt_dict:
            logging.warning(f"Worker #{index}: Bỏ qua vì không tạo được prompt.")
            return

        # --- THAY ĐỔI MỚI BẮT ĐẦU TẠI ĐÂY ---

        # 1.A. In enriched_prompt ra console log để xem real-time
        # Sử dụng json.dumps với indent để dễ đọc trên console
        pretty_prompt = json.dumps(enriched_prompt_dict, indent=2, ensure_ascii=False)
        logging.info(f"Worker #{index}: Enriched Prompt được tạo:\n{pretty_prompt}")

        # --- THAY ĐỔI Ở ĐÂY ---
        # Đổi tên file thành .json cho đúng với định dạng ghi
        prompt_output_filename = f"alert_enrichment_{index}.jsonl" 
        prompt_output_path = os.path.join(ENRICHED_PROMPTS_DIR, prompt_output_filename)

        try:
            os.makedirs(ENRICHED_PROMPTS_DIR, exist_ok=True)
            with open(prompt_output_path, 'w', encoding='utf-8') as f_prompt:
                json.dump(enriched_prompt_dict, f_prompt, indent=4, ensure_ascii=False)
            logging.info(f"Worker #{index}: Đã lưu enriched prompt vào: {prompt_output_path}")
        except Exception as e:
            logging.error(f"Worker #{index}: Không thể lưu enriched prompt vào file. Lỗi: {e}")
        
        # --- THAY ĐỔI MỚI KẾT THÚC TẠI ĐÂY ---

        # # 2. Gọi LLM
        # alert_name = alert.get('rule', {}).get('name', '')
        # example_path = select_example_path(alert_name)
        # with open(example_path, "r", encoding='utf-8') as f:
        #     example_content = f.read()
        # final_system_prompt = system_prompt_template.replace("{{EXAMPLE_PLACEHOLDER}}", example_content)
        prompt_as_json_string = json.dumps(enriched_prompt_dict) # Không cần indent khi gửi cho LLM
        
        llm_result = None
        if TEST_MODE is True:
            logging.info(f"Worker #{index}: Chạy ở chế độ TEST, bỏ qua gọi LLM.")
            llm_result = {
                "summary": "This is a test result.",
                "severity": "TEST",
                "recommendation": "No action needed, this is a test."
            }
        else:
            logging.info(f"Worker #{index}: Gửi yêu cầu đến LLM...")            
            start_llm = time.monotonic()
            llm_result = llm_client.get_classification(prompt_as_json_string)
            end_llm = time.monotonic()
        
            if not llm_result:
                logging.error(f"Worker #{index}: LLM không trả về kết quả hợp lệ.")
                return
        
            logging.info(f"Worker #{index}: LLM inference mất {end_llm - start_llm:.2f} giây.")

        # 3. Tạo bản ghi kết quả
        output_record = {
            "alert_index": index,
            "processed_at": datetime.now().isoformat(),
            "original_alert_signature": alert.get('rule', {}).get('name', 'N/A'),
            "enriched_prompt_file": prompt_output_path, # Thêm đường dẫn đến file prompt để tiện tra cứu
            "llm_analysis": llm_result
        }
        
        # 4. Ghi kết quả vào file
        with lock:
            output_file_handle.write(json.dumps(output_record) + '\n')
            output_file_handle.flush() 
            logging.info(f"Worker #{index}: Đã ghi kết quả vào file.")
            
    except Exception as e:
        logging.error(f"Worker #{index}: Lỗi không xác định khi xử lý alert.", exc_info=True)

# Hàm follow() và main() giữ nguyên không thay đổi
def follow(the_file):
    """Generator mô phỏng hành vi 'tail -f'."""
    the_file.seek(0, 2)  # Đi đến cuối file
    while True:
        line = the_file.readline()
        if not line:
            time.sleep(0.1)  # Đợi một chút nếu không có dòng mới
            continue
        yield line

def main():
    logging.info(f"--- BẮT ĐẦU DỊCH VỤ GIÁM SÁT FILE: {ALERTS_FILE_PATH} ---")
    logging.info("Nhấn Ctrl+C để dừng chương trình.")
    
    manager = EnrichmentManager()
    llm_client = LLMClient()
    lock = threading.Lock() # Tạo một khóa để bảo vệ việc ghi file
    
    # try:
    #     with open(SYSTEM_PROMPT_TEMPLATE_PATH, 'r', encoding='utf-8') as f:
    #         system_prompt_template = f.read()
    # except FileNotFoundError:
    #     logging.error(f"Lỗi: Không tìm thấy system prompt template. Dừng chương trình.")
    #     return

    # Mở file input và output, và giữ chúng mở trong suốt quá trình chạy
    try:
        with open(ALERTS_FILE_PATH, 'r', encoding='utf-8') as input_file, \
             open(FINAL_ANALYSIS_OUTPUT_PATH, 'a', encoding='utf-8') as output_file, \
             ThreadPoolExecutor(max_workers=MAX_WORKERS, thread_name_prefix='Worker') as executor:
            
            # Bỏ qua các dòng đã có sẵn trong file log, chỉ xử lý dòng mới
            # Nếu bạn muốn xử lý cả các dòng cũ, hãy xóa dòng này.
            logging.info("Đã mở file log, di chuyển đến cuối file để giám sát các alert mới...")
            input_file.seek(0, 2)
            
            alert_counter = get_next_alert_index(ENRICHED_PROMPTS_DIR)
            # Vòng lặp vô tận để đọc các dòng mới
            while True:
                line = input_file.readline()
                if not line:
                    time.sleep(1) # Đợi 1 giây nếu không có gì mới
                    continue

                logging.info(f"Phát hiện alert mới #{alert_counter}. Gửi đi xử lý...")
                # try:
                #     alert_object = json.loads(line)
                #     # Giao việc cho một worker trong pool
                #     executor.submit(
                #         process_and_write_alert,
                #         manager, llm_client, alert_object, alert_counter,
                #         output_file, lock
                #     )
                #     alert_counter += 1
                # except json.JSONDecodeError:
                #     logging.warning(f"Bỏ qua dòng không hợp lệ: {line.strip()}")
                try:
                    # Chuyển đổi từ JSON string thành DataFrame để xử lý
                    new_alerts_df = pd.read_json(line, lines=True)
                    
                    # Lặp qua từng hàng (mỗi hàng là một alert) và giao việc
                    for index, alert_row in new_alerts_df.iterrows():
                        logging.info(f"Phát hiện alert mới #{alert_counter}. Gửi đi xử lý...")
                        executor.submit(
                            process_and_write_alert,
                            manager, llm_client, alert_row, alert_counter,
                            output_file, lock
                        )
                        alert_counter += 1

                except (json.JSONDecodeError, ValueError):
                    logging.warning(f"Bỏ qua dòng không hợp lệ: {line.strip()}")
                    
    except FileNotFoundError:
        logging.error(f"Lỗi: File log '{ALERTS_FILE_PATH}' không tồn tại. Hãy tạo file trước khi chạy.")
    except KeyboardInterrupt:
        logging.info("--- NHẬN TÍN HIỆU DỪNG (Ctrl+C). KẾT THÚC DỊCH VỤ ---")
    except Exception as e:
        logging.error(f"Lỗi nghiêm trọng xảy ra: {e}", exc_info=True)
    finally:
        # Đảm bảo đóng các tài nguyên khi kết thúc
        if 'executor' in locals() and executor:
            executor.shutdown(wait=True)
            logging.info("Đã đóng ThreadPoolExecutor.")
        if 'input_file' in locals() and not input_file.closed:
            input_file.close()
        if 'output_file' in locals() and not output_file.closed:
            output_file.close()
        logging.info("--- DỊCH VỤ ĐÃ DỪNG ---")
## <<< THAY ĐỔI KẾT THÚC >>>

if __name__ == "__main__":
    main()