# security_onion_llm_project/main.py

import json
import logging
from enrichment_manager2 import EnrichmentManager
from concurrent.futures import ThreadPoolExecutor, as_completed
from llm_client2 import LLMClient
import time
import os
LOG_FORMAT = "%(asctime)s [%(threadName)-12.12s] [%(levelname)-5.5s]  %(message)s"
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)



# ********* TEST ALERTs ** *******

# name_alert = '200_alerts'
# ALERTS_FILE_PATH = f"./so_alerts/ground_truth/{name_alert}.json"
# FINAL_ANALYSIS_OUTPUT_PATH = f"./user_prompt/ground_truth/{name_alert}.json"

# name_alert = '4'
# ALERTS_FILE_PATH = f"./so_alerts/ground_truth/{name_alert}.json"
# FINAL_ANALYSIS_OUTPUT_PATH = f"./user_prompt/ground_truth/{name_alert}.json"


name_alert = 'alerts_all-2025-08-13'
ALERTS_FILE_PATH = f"./so_alerts/{name_alert}.jsonl"
# FINAL_ANALYSIS_OUTPUT_PATH = f"./user_prompt/{name_alert}.json"


# ********* TEST ALERTs *********

# name_alert = '1'
# ALERTS_FILE_PATH = f"./so_test_alerts/ground_truth/{name_alert}.json"
# FINAL_ANALYSIS_OUTPUT_PATH = f"./user_prompt/{name_alert}.json"

# name_alert = 'files_alert'
# ALERTS_FILE_PATH = f"./so_test_alerts/{name_alert}.json"

# Outputs
OUTPUTS_BASE_DIR = "./outputs"
FINAL_ANALYSIS_DIR = f"{OUTPUTS_BASE_DIR}/final_analysis"
ENRICHED_PROMPTS_DIR = f"{OUTPUTS_BASE_DIR}/enriched_prompts/"
FINAL_ANALYSIS_OUTPUT_PATH = f"{FINAL_ANALYSIS_DIR}/{name_alert}_analysis.jsonl"

MAX_WORKERS = 10 
               
def process_single_alert(manager: EnrichmentManager, llm_client: LLMClient, alert: dict, index: int) -> dict | None:
    """Hàm để xử lý một alert duy nhất, bao gồm làm giàu và phân loại bởi LLM."""
    try:
        logging.info(f"Worker #{index}: Bắt đầu xử lý alert...")
        
        # --- ĐO THỜI GIAN ENRICHMENT ---
        start_enrich = time.monotonic()
        enriched_prompt_dict  = manager.enrich_and_prompt(alert)
        end_enrich = time.monotonic()
        logging.info(f"Worker #{index}: Thời gian làm giàu: {end_enrich - start_enrich:.2f} giây.")  
        # --------------------------------      
        
        if not enriched_prompt_dict:
            logging.warning(f"Worker #{index}: Bỏ qua vì không tạo được prompt.")
            return None
        
        # --- LƯU PROMPT ĐÃ LÀM GIÀU ---                
        enriched_prompt_output_path = f"{ENRICHED_PROMPTS_DIR}/alert_enrichment_{index}.json"
        try:
            # Đảm bảo thư mục tồn tại
            import os
            os.makedirs(ENRICHED_PROMPTS_DIR, exist_ok=True)
            with open(enriched_prompt_output_path, "w", encoding='utf-8') as f_prompt:
                json.dump(enriched_prompt_dict, f_prompt, indent=2, ensure_ascii=False)
        except IOError as e:
            logging.error(f"Worker #{index}: Lỗi khi ghi file prompt trung gian: {e}")
        
        prompt_as_json_string = json.dumps(enriched_prompt_dict) 
         # --- -------------------- ---           
         
         
        test = True
        if test is True:
            llm_result = {}
            if not llm_result:
                pass
        else:
            start_llm = time.monotonic()
            llm_result = llm_client.get_classification(prompt_as_json_string)
            end_llm = time.monotonic()
            logging.info(f"Worker #{index}: Thời gian LLM inference: {end_llm - start_llm:.2f} giây.")
            if not llm_result:
                logging.error(f"Worker #{index}: LLM không trả về kết quả hợp lệ.")
                return None
    
        output_record = {
            "alert_index": index,
            "original_alert": {
                "timestamp": alert.get('@timestamp'),
                "signature": alert.get('rule', {}).get('name', 'N/A'),
            },
            "llm_analysis": llm_result
        }
        logging.info(f"Worker #{index}: Hoàn thành xử lý.")
        return output_record

    except Exception as e:
        logging.error(f"Worker #{index}: Lỗi không xác định khi xử lý alert.", exc_info=True)
        return None

def main():
    logging.info("--- BẮT ĐẦU QUÁ TRÌNH PHÂN TÍCH HÀNG LOẠT ---")
        
    manager = EnrichmentManager()
    llm_client = LLMClient()
    
    # Nếu bạn muốn đọc từ file JSON, hãy sử dụng đoạn mã sau:
    # try:
    #     with open(ALERTS_FILE_PATH, 'r', encoding='utf-8') as f:
    #         alerts_to_process = json.load(f)
    #     logging.info(f"Đã tải {len(alerts_to_process)} cảnh báo từ '{ALERTS_FILE_PATH}'.")
    # except (FileNotFoundError, json.JSONDecodeError) as e:
    #     logging.error(f"Lỗi khi đọc file cảnh báo: {e}")
    #     return

    # # Nếu bạn muốn đọc từ file JSONL, hãy sử dụng đoạn mã sau:
    alerts_to_process = []
    try:
        with open(ALERTS_FILE_PATH, 'r', encoding='utf-8') as f:
            # Lặp qua từng dòng trong file
            for line in f:
                # Bỏ qua các dòng trống có thể có
                if not line.strip():
                    continue
                try:
                    # Dùng json.loads() để parse từng dòng
                    alert = json.loads(line)
                    alerts_to_process.append(alert)
                except json.JSONDecodeError:
                    logging.warning(f"Bỏ qua dòng JSON không hợp lệ: {line.strip()}")

        logging.info(f"Đã tải {len(alerts_to_process)} cảnh báo từ '{ALERTS_FILE_PATH}'.")

    except FileNotFoundError:
        logging.error(f"Lỗi: Không tìm thấy file cảnh báo '{ALERTS_FILE_PATH}'.")
        return

    
    
    # Khôi phục logic ghi file JSONL
    os.makedirs(FINAL_ANALYSIS_DIR, exist_ok=True)    
    with open(FINAL_ANALYSIS_OUTPUT_PATH, "w", encoding='utf-8') as f_out:
        # Khôi phục logic xử lý song song với ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=MAX_WORKERS, thread_name_prefix='Worker') as executor:
            future_to_index = {
                executor.submit(process_single_alert, manager, llm_client, alert, i): i 
                for i, alert in enumerate(alerts_to_process, 1)
            }
            
            processed_count = 0
            for future in as_completed(future_to_index):
                result_record = future.result()
                if result_record:
                    f_out.write(json.dumps(result_record) + '\n')
                    processed_count += 1

    logging.info(f"--- KẾT THÚC QUÁ TRÌNH ---")
    logging.info(f"Đã xử lý và ghi ra file thành công {processed_count} / {len(alerts_to_process)} bản ghi.")


if __name__ == "__main__":
    main()