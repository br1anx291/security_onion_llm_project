# security_onion_llm_project/main.py

import json
import logging
from enrichment_manager import EnrichmentManager
from concurrent.futures import ThreadPoolExecutor, as_completed


LOG_FORMAT = "%(asctime)s [%(threadName)-12.12s] [%(levelname)-5.5s]  %(message)s"
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)

ALERTS_FILE_PATH = "./so_alerts/alerts_ids2017_thur.json"
OUTPUT_FILE_PATH = "./user_prompt/ids2017_thur_enriched_prompts.txt" 

# ALERTS_FILE_PATH = "./so_test_alerts/4log.json"
# OUTPUT_FILE_PATH = "./user_prompt/4log.txt"

MAX_WORKERS = 10 

# "./dns_alert.json"
# "./http_alert.json"
# "./files_alert.json"
# "./ssl_alert.json"

def process_single_alert(manager, alert, index):
    """Hàm để xử lý một alert duy nhất, dùng cho việc xử lý song song."""
    try:
        logging.info(f"Bắt đầu xử lý alert #{index}")
        alert_name = alert.get('rule', {}).get('name', 'N/A')
        
        final_prompt = manager.enrich_and_prompt(alert)
        
        logging.info(f"Hoàn thành xử lý alert #{index} - Tên: {alert_name}")
        
        # === DÒNG SỬA QUAN TRỌNG NHẤT LÀ ĐÂY ===
        # Phải trả về cả index và prompt
        return index, final_prompt

    except Exception:
        # Khi có lỗi cũng phải trả về 2 giá trị
        alert_name = alert.get('rule', {}).get('name', 'N/A')
        logging.error(f"LỖI khi xử lý alert #{index}: {alert_name}", exc_info=True)
        return index, None

def main():
    """
    Hàm chính để chạy thử nghiệm toàn bộ luồng làm việc.
    Đọc các cảnh báo từ một file JSON và xử lý từng cái một.
    """
    logging.info("--- BẮT ĐẦU QUÁ TRÌNH LÀM GIÀU HÀNG LOẠT (SONG SONG) ---")
        
    # Khởi tạo bộ não của hệ thống một lần duy nhất
    manager = EnrichmentManager()
    
    # Đọc và parse file JSON chứa danh sách các alert
    try:
        with open(ALERTS_FILE_PATH, 'r', encoding='utf-8') as f:
            alerts_to_process = json.load(f)
        print(f"Tìm thấy {len(alerts_to_process)} cảnh báo trong file '{ALERTS_FILE_PATH}'.")
    except FileNotFoundError:
        print(f"LỖI: Không tìm thấy file '{ALERTS_FILE_PATH}'. Vui lòng tạo file này.")
        return
    except json.JSONDecodeError:
        print(f"LỖI: File '{ALERTS_FILE_PATH}' không chứa định dạng JSON hợp lệ.")
        return  

  # Dùng dictionary để lưu kết quả, giúp dễ dàng sắp xếp lại nếu cần
    results = {}
    with ThreadPoolExecutor(max_workers=MAX_WORKERS, thread_name_prefix='Worker') as executor:
        future_to_alert = {
            executor.submit(process_single_alert, manager, alert, i): i 
            for i, alert in enumerate(alerts_to_process, 1)
        }
        
        for future in as_completed(future_to_alert):
            index, prompt = future.result()
            if prompt:
                results[index] = prompt

    logging.info("--- KẾT THÚC QUÁ TRÌNH XỬ LÝ ---")
    logging.info(f"Đã xử lý và tạo prompt thành công cho {len(results)} / {len(alerts_to_process)} cảnh báo.")
    
    # === BẮT ĐẦU PHẦN THAY ĐỔI: GHI TẤT CẢ PROMPT RA FILE ===
    if results:
        logging.info(f"Bắt đầu ghi {len(results)} prompts ra file '{OUTPUT_FILE_PATH}'...")
        try:
            with open(OUTPUT_FILE_PATH, "w", encoding='utf-8') as f:
                # Sắp xếp các prompt theo đúng thứ tự của alert ban đầu
                
                f.write(f"""
### BỐI CẢNH HỆ THỐNG ###
BẠN LÀ một mô hình ngôn ngữ lớn được tinh chỉnh cho nhiệm vụ phân tích an ninh mạng.
VAI TRÒ CỦA BẠN là một chuyên gia phân tích SOC Cấp 2, có nhiệm vụ thẩm định các cảnh báo bằng cách suy luận logic dựa trên bằng chứng được cung cấp.

### YÊU CẦU NHIỆM VỤ ###
Thực hiện một quy trình phân tích gồm 2 phần: (A) SUY LUẬN TỪNG BƯỚC và (B) KẾT LUẬN CUỐI CÙNG.

#### (A) SUY LUẬN TỪNG BƯỚC (CHAIN OF THOUGHT):
Hãy viết ra quá trình suy nghĩ của bạn theo các bước sau để đi đến kết luận:
1.  **Phân tích Cảnh báo gốc:** Ý nghĩa của signature "ETPRO TROJAN Win32/Dridex SSL Certificate Observed" là gì?
2.  **Đánh giá Bằng chứng Sơ cấp:** Thông tin từ `ssl.log` (subject, issuer, validation_status) cho thấy điều gì bất thường? Gợi ý hệ thống về JA3 hash có ý nghĩa gì?
3.  **Đối chiếu với Bằng chứng Thứ cấp:** Thông tin từ `dns.log` có xác nhận hay mâu thuẫn với bằng chứng sơ cấp không?
4.  **Phân tích Bằng chứng Phủ định:** Sự vắng mặt của log HTTP có ý nghĩa gì trong bối cảnh một kết nối SSL đáng ngờ?
5.  **Tổng hợp Suy luận:** Liên kết tất cả các điểm trên lại. Mức độ trùng khớp và tin cậy của các bằng chứng là cao hay thấp? Tại sao?

#### (B) KẾT LUẬN CUỐI CÙNG:
Dựa trên quá trình suy luận ở trên, hãy cung cấp kết luận theo định dạng JSON nghiêm ngặt sau đây. Không thêm bất kỳ văn bản nào khác.

{
  "classification": "...",
  "reasoning_summary": "..."
}

### DỮ LIỆU ĐẦU VÀO ###
Dưới đây là một bộ dữ liệu đã được thu thập và tiền xử lý, bao gồm cảnh báo gốc và các bằng chứng liên quan
""")
                for i in sorted(results.keys()):
                    prompt = results[i]
                    f.write(f"========================= PROMPT CHO ALERT #{i} =========================\n\n")
                    f.write(prompt)
                    f.write("\n\n\n") # Thêm khoảng trắng để dễ đọc
            logging.info(f"Đã ghi thành công tất cả prompts vào file '{OUTPUT_FILE_PATH}'")
        except Exception as e:
            logging.error(f"Không thể ghi file output: {e}", exc_info=True)
    # === KẾT THÚC PHẦN THAY ĐỔI ===


if __name__ == "__main__":
    main()