# FILE: llm_client.py

import json
import logging
import time
from typing import Dict
import requests
import re
import socket
from json_repair import repair_json

USER_INSTRUCTION_TEMPLATE = """
**Based on the Persona, KNOWLEDGE BASE: SECURITY KEYWORDS, CRITICAL RULE, provided in your system instructions, analyze the following CONTEXT and execute the TASK exactly as specified below.**

# CRITICAL INSTRUCTIONS:
# 1. **YOUR FIRST AND ONLY GOAL FOR 'thought_process' is to build the list of signal mappings. Do not synthesize or conclude anything in that field.**
# 2. For 'evaluate_signals', analyze ONLY the signals you marked as `is_significant: true` in your 'thought_process'.
# 3. Be brief and to the point.
# 4. Do NOT repeat information between the 'analyze_alert', 'evaluate_signals', and 'synthesize_reasoning' fields. Each field has a unique purpose.

# CONTEXT
{{ENRICHED_PROMPT}}

# TASK
Analyze the each value in provided CONTEXT. Your response MUST be a SINGLE, FLAWLESS, and **PERFECTLY VALID JSON OBEJECT**. Do not include any text outside the JSON.


## JSON OBJECT
{
  "result": {
    "reasoning": {
        "thought_process": [
        {
            "signal_found": "string", // The exact key with value pair found in the CONNECTION JSON and EVIDENCE JSON.
            "knowledge_base_mapping": "string", // The corresponding `Category:Weight:Interpretation` from the KB. If not found, state 'Not in KB'.
            "is_significant": "boolean" // True if weight >= 5 or is a direct malware signature, otherwise False.
        }
        ], // Step 1: BUILD THIS LIST. Iterate through the CONTEXT JSON. For each relevant piece of data, create an object in this list mapping it to the KNOWLEDGE BASE.
      "analyze_alert": "string",   // For each key in ALERT NAME. Aanswer: 1. What is it? 2. What is its malicious tactic or purpose? Combine answers into a paragraph. Just analyze ONLY alert name. 
      "evaluate_signals": "string",// Using ONLY the significant signals from 'thought_process', briefly state the evidence found.
      "synthesize_reasoning": "string" // Synthesize the conclusions from 'analyze_alert' and 'evaluate_signals' into a brief, chronological narrative of the event. If malicious, describe the attack steps. If benign, describe the normal user or system's actions. Do not state the final classification here. 
    "conclusion": {
      "classification": "string", // Based on your reasoning, classify as "True Positive", "False Positive", or "Unable to determine".
      "confidence_score": "number", // Based on your reasoning, provide a confidence score from 0.0 (low) to 1.0 (high) for your classification.
      "reasoning_summary": "string" // Based on your reasoning, provide a one-sentence summary with SIGNALS (under 25 words).
    }
  }
}

"""


# ==============================================================================
# CONFIGURATION - CẤU HÌNH
# ==============================================================================
# Chuyển thành True để gọi API qua ngrok (public), False để gọi API trong mạng nội bộ (local)
USE_REMOTE = False 
# --- Cấu hình cho môi trường REMOTE (Ngrok) ---
REMOTE_API_URL = "https://c55820cde7c4.ngrok-free.app/v1/chat/completions"
REMOTE_MODEL_NAME = "meta-llama-3-8b-instruct"


ipv4 = '192.168.1.76'
LOCAL_API_URL = f"http://{ipv4}:8080/v1/chat/completions"
LOCAL_MODEL_NAME = "D:\FPT_CAPSTONE\2025CAPSTONE\1_Source_Code\security_onion_llm_project\llm_model\Meta-Llama-3-8B-Instruct.Q4_K_M.gguf"



# Thiết lập logging cơ bản
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


class LLMClient:
    def __init__(self):
        """
        Khởi tạo LLMClient và thiết lập cấu hình API dựa trên cờ USE_REMOTE.
        """
        if USE_REMOTE:
            self.api_url = REMOTE_API_URL
            self.model_name = REMOTE_MODEL_NAME
            mode = f"REMOTE (Ngrok: {self.api_url})"
        else:
            self.api_url = LOCAL_API_URL
            self.model_name = LOCAL_MODEL_NAME
            mode = f"LOCAL (LAN: {self.api_url})"
            
        logging.info(f"LLMClient initialized. Mode: {mode}")

    def get_classification(self, system_prompt: str, enriched_prompt: str) -> Dict | None:
        user_prompt = USER_INSTRUCTION_TEMPLATE.replace("{{ENRICHED_PROMPT}}", enriched_prompt)
        
        # Bỏ logging system_prompt ở đây cho đỡ dài log
        # logging.info("="*20 + " SYSTEM PROMPT " + "="*20)
        # logging.info(system_prompt)
        
        logging.info("="*20 + " USER PROMPT " + "="*20)
        logging.info(user_prompt)

        return self._query_llm_api(system_prompt, user_prompt)

    def _query_llm_api(self, system_prompt: str, user_prompt: str) -> Dict | None:
        """
        Gửi yêu cầu đến API LLM (local hoặc remote) và trả về kết quả.
        Hàm này được dùng cho cả hai chế độ.
        """
        headers = {"Content-Type": "application/json"}
        payload = {
            "model": self.model_name,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            "temperature": 0.0,
            "max_tokens": 2048,
            # Một số API (như llama.cpp) yêu cầu `stream: false` để trả về JSON hoàn chỉnh
            "stream": False,
            "cache_prompt": False 
        }

        try:
            start_time = time.monotonic()
            logging.info(f"Sending request to {self.api_url} with model '{self.model_name}'...")
            
            response = requests.post(self.api_url, headers=headers, data=json.dumps(payload))
            response.raise_for_status()  # Báo lỗi nếu status code là 4xx hoặc 5xx
            
            result = response.json()
            message_content = result["choices"][0]["message"]["content"]
            
            logging.info(f"Response received in {time.monotonic() - start_time:.2f}s:\n{message_content}")
            return self.extract_json(message_content)
            
        except requests.exceptions.RequestException as e:
            logging.error(f"Error calling LLM API at {self.api_url}: {e}", exc_info=True)
            return None
        except Exception as e:
            logging.error(f"An unexpected error occurred: {e}", exc_info=True)
            return None


    # === EXTRACT JSON FROM RESPONSE ===
    def extract_json(self, message_content: str) -> Dict | None:
        try:
            json_start = message_content.find('{')
            json_end = message_content.rfind('}')
            if json_start == -1 or json_end == -1:
                logging.error("No JSON block found in LLM response.")
                return None
            json_string = message_content[json_start: json_end + 1]
            return json.loads(json_string)
        except json.JSONDecodeError as e:
            logging.warning(f"Initial JSON decode failed: {e}. Attempting auto-correction...")

            try:
                # Sử dụng repair_json để sửa chuỗi
                repaired_string = repair_json(json_string)
                
                logging.info("Sửa lỗi JSON thành công. Đang phân tích lại chuỗi đã sửa.")
                # Phân tích cú pháp chuỗi đã được sửa
                return json.loads(repaired_string)

            except Exception as final_e:
                # 4. Nếu ngay cả việc sửa lỗi cũng thất bại
                logging.error(f"Không thể sửa hoặc phân tích JSON ngay cả sau khi dùng json_repair. Lỗi cuối cùng: {final_e}")
                logging.error(f"Nội dung gốc bị lỗi: {json_string}")
                return None
            
    # def extract_json(self, message_content: str) -> dict | None:
    #     """
    #     Trích xuất và sửa lỗi một khối JSON cụ thể từ chuỗi đầu vào,
    #     nhắm mục tiêu vào khối JSON chứa key "result".
    #     """
    #     try:
    #         # 1. THAY ĐỔI LOGIC: Tìm điểm bắt đầu của khối JSON chứa "result".
    #         # Thay vì tìm '{' đầu tiên, ta tìm vị trí của key "result".
    #         keyword = '"result":'
    #         keyword_pos = message_content.find(keyword)

    #         if keyword_pos == -1:
    #             logging.error("Không tìm thấy keyword 'result' trong chuỗi.")
    #             return None

    #         # Sau khi thấy keyword, tìm ngược lại để lấy dấu '{' mở đầu của block đó.
    #         json_start = message_content.rfind('{', 0, keyword_pos)

    #         if json_start == -1:
    #             logging.error("Không tìm thấy dấu '{' mở đầu cho khối JSON chứa 'result'.")
    #             return None

    #         # 2. THAY ĐỔI LOGIC: Tìm dấu '}' đóng tương ứng một cách chính xác.
    #         # Thay vì tìm '}' cuối cùng, ta đếm số lượng ngoặc để tìm đúng cặp.
    #         open_braces = 0
    #         json_end = -1
    #         for i in range(json_start, len(message_content)):
    #             char = message_content[i]
    #             if char == '{':
    #                 open_braces += 1
    #             elif char == '}':
    #                 open_braces -= 1
                
    #             # Khi số ngoặc mở/đóng cân bằng (bằng 0), ta đã tìm thấy dấu '}' của khối.
    #             if open_braces == 0:
    #                 json_end = i
    #                 break
            
    #         if json_end == -1:
    #             logging.error("Không tìm thấy dấu '}' đóng tương ứng cho khối JSON.")
    #             return None

    #         # 3. GIỮ NGUYÊN LOGIC: Trích xuất và dùng repair_json như cũ.
    #         # Logic từ đây trở đi được giữ nguyên, nhưng áp dụng trên chuỗi đã được lọc chính xác.
    #         json_string = message_content[json_start : json_end + 1]
            
    #         try:
    #             return json.loads(json_string)
    #         except json.JSONDecodeError as e:
    #             logging.warning(f"JSON bị lỗi, đang tự động sửa: {e}")
    #             try:
    #                 repaired_string = repair_json(json_string)
    #                 logging.info("Sửa lỗi JSON thành công. Đang phân tích lại...")
    #                 return json.loads(repaired_string)
    #             except Exception as final_e:
    #                 logging.error(f"Không thể phân tích JSON ngay cả sau khi sửa lỗi. Lỗi cuối cùng: {final_e}")
    #                 logging.error(f"Chuỗi JSON gốc bị lỗi: {json_string}")
    #                 return None

    #     except Exception as outer_e:
    #         logging.error(f"Lỗi không xác định trong quá trình trích xuất JSON: {outer_e}")
    #         return None