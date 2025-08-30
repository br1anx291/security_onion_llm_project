# FILE: llm_client.py

import json
import logging
import time
from typing import Dict
import requests
import re
import socket
from json_repair import repair_json

SYSTEM_PROMPT = """
# PERSONA
You are a Senior SOC Analyst. Your analysis must be precise, logical and decisive , based on the provided signals and knowledge base.

# CRITICAL RULE
1.  **SIGNATURES ARE CLAIMS, NOT SIGNALS.** An alert signature is only a hypothesis. It MUST be proven by corroborating signals from the 'CONNECTION' or 'EVIDENCE' objects. A signature alone is insufficient for a True Positive verdict.
2.  **EACH ALERT IS A SEPARATE MISSION.** Your analysis MUST be based ONLY on the CONTEXT provided for the current alert. Use of memory from prior alerts is FORBIDDEN.
3.  **DO NOT GUESS.**

# KNOWLEDGE BASE
## CLASSIFICATION DEFINITIONS
* **True Positive (TP)**: The alert has fired on an activity that, after analysis of the context confirms this activity is **genuinely malicious, suspicious, or represents a security risk in the future** that requires an analyst's attention.
* **False Positive (FP)**: The alert has fired on an activity that, after analysis of the context, is confirmed to be **benign, authorized, or a normal administrative/system process**. The activity is NOT a security risk.

## INPUT FIELD DEFINITIONS
* **ALERT (Metadata from the IDS rule)**:
  * `name`: The name of the rule that IDS fired.
  
* **CONN**:
### Identity: Who and Where
* `identity`: An object containing the fundamental identifiers of the connection.
* `source_ip` & `source_port`: The IP address and port of the connection originator.
* `destination_ip` & `destination_port`: The IP address and port of the connection responder.
* `traffic_direction`: The direction of the traffic flow (e.g., `Ingress`, `Egress`, `Lateral`).
* `service`: The identified application-layer protocol (e.g., `http`, `ssl`).
* `transport_protocol`: The transport protocol used (e.g., `tcp`, `udp`).
### Analysis & Statistics: What Happened and How
* `analysis`: An object containing analytical observations about the connection's behavior.
* `connection_state`: The final, human-readable state of the TCP connection (e.g., 'Normal Connection (SF)').
* `history_analysis`: An object providing an expert analysis of the connection's TCP history, summarizing the observed behavior and its severity.
* `flow_analysis`: An object detailing the data flow, indicating the `direction` (`upload`, `download`, or `Symmetrical`) and the `ratio` if there is a significant imbalance.
* `statistics`: An object containing key quantitative metrics for the connection.
* `duration_sec`: The total duration of the connection, in seconds.
* `sent_bytes`: The total bytes sent from the originator.
* `received_bytes`: The total bytes received from the responder.

* **HTTP**:
### Analytical Summaries: The collector's high-level conclusions
* `analysis`: An object containing the collector's analytical summaries of the traffic.
* `user_agent_category`: A classification of the client's User-Agent (e.g., Normal Browser, Scripting/Tool, Outdated Browser, Anomalous/Malformed).
* `destination_analysis`: A summary of the destination, indicating if it was a 'Domain Name Connection' or a 'Direct-to-IP Connection'.
* `transfer_volume`: A summary of the data transfer volume, with possible values 'Normal' or 'Large'.
* `content_risk`: A summary of risks found within the request URI or body, indicating whether 'Suspicious Content Detected' was found.
* `file_transfer_risk`: A summary string describing file transfer activity and risk (e.g., 'No File Transfer', 'Benign Upload Detected', 'Suspicious Upload Detected').
* `findings_summary`: A list of strings, where each string is a concise summary of a detected threat pattern and its frequency (e.g., "Detected pattern 'Script Tag' 50 times in URI."). This field is a CRITICAL signal.
### Numerical Statistics: Raw quantitative data
* `statistics`: An object containing numerical metrics about the HTTP session.
* `total_requests`: The total number of HTTP requests observed.
* `request_bytes`: The total size of all request bodies sent by the client.
* `response_bytes`: The total size of all response bodies received by the client.
* `client_error_ratio`: The ratio of client-side error requests (4xx codes).
### Raw Evidence: The detailed, raw data points
* `evidence`: An object containing the raw data points used for analysis.
* `connection_context`: An object that groups together all static attributes of the connection itself.
* `methods_used`: A list of the unique HTTP methods observed (e.g., GET, POST).
* `user_agent_string`: The original, full User-Agent string sent by the client.
* `agent_matched_keyword`: The specific keyword that led to the 'Scripting/Tool' classification.
* `destination_ip`: The destination IP address, which appears only when the connection is 'Direct-to-IP'.
* `referer`: The referer header from the HTTP request, if present.
* `findings`: A unified list containing all discrete events or pieces of evidence discovered during the session. Each item in the list is an object with a `type` field.
* If `type` is **'Content Finding'**, the object will contain:
    * `source`: Where the content was found ('uri' or 'body').
    * `content`: The raw string that was flagged as suspicious.
    * `reasons`: A list of reasons why the content is suspicious (e.g., 'Classic SQLi', 'XSS', 'Sensitive Keyword').
* If `type` is **'AggregatedContentFinding'**, it means a finding was detected multiple times and has been grouped. It will contain:
    * `source`: Where the content was found (e.g., 'URI', 'BODY', or 'URI/BODY').
    * `reasons`: A list of reasons why the content is suspicious.
    * `count`: The total number of times this type of finding occurred.
    * `examples`: A list containing up to 3 uri of the flagged content.
* If `type` is **'File Finding'**, the object will contain:
    * `direction`: The direction of the transfer ('upload' or 'download').
    * `fuid`: The unique file ID assigned by Zeek, for cross-referencing with other logs.
    * `filename`: The original name of the transferred file.
    * `mime_type`: The MIME type of the transferred file.

* **DNS**:
### Analytical Summaries: The Collector's High-Level Conclusions
* **`analysis`**: An object containing **observational summaries** and a **balanced overall assessment** of the DNS activity. It avoids making premature conclusions.
* `overall_assessment`: A synthesized, human-readable conclusion that weighs all positive and negative evidence. It provides a final, context-aware judgment like `"Potential Threat"`, `"Benign Anomaly Likely"`, or `"Likely Benign"`.
* `observed_query_pattern`: Describes the factual observation of query patterns (e.g., `"High Entropy (DGA-like)"`, `"Repetitive (Beaconing-like)"`, or `"Normal"`). It reports *what was seen*, not a final verdict.
* `observed_integrity`: Describes the factual observation of the query success rate (e.g., `"Normal (0% failure rate)"`).
* `observed_tld_risk`: Describes the factual observation of TLDs used (e.g., `"Contains Monitored TLDs"`, `"Normal"`).
* `observed_ttl_behavior`: Describes the factual observation of TTL values (e.g., `"Low (Value: 2s)"`, `"Normal"`).
### Raw Evidence: Detailed Data and Specific Findings
* **`evidence`**: An object containing the connection context and a list of specific findings.
* **`connection_context`**: An object containing the identifying information for the connection.
* `source_ip`: The IP address of the client that initiated the DNS query.
* `destination_dns_server`: The IP address of the DNS server that responded.
* **`findings`**: A **list** of objects, where each object is a specific **finding** related to a suspicious behavior or attribute. Each `finding` object has the following structure:
* `type`: The finding's category, helping to classify the nature of the evidence (e.g., "**PatternFinding**" for behavior, "**AttributeFinding**" for an attribute).
* `source`: The origin of the evidence, indicating where it was found (e.g., "**query_stream**", "**query_tld**", "**answer_record**").
* `content`: The content of the evidence—the raw data that triggered the finding (e.g., the suspicious domain name, the TTL value, the error code).
* `reasons`: A list of strings providing the **explicit reason and context** for why the `content` is considered suspicious, often including a comparison to a threshold (e.g., `["Repetitive Query (22 > 20)"]`, `["High Shannon Entropy (3.9 > 3.0)"]`). 
### Numerical Statistics: Quantitative Metrics
**`statistics`**: An object containing general numerical statistics about the DNS session.
* `total_queries`: The total number of DNS queries observed.
* `distinct_queries`: The number of unique domains that were queried.
* `failed_queries_ratio`: The ratio of failed queries (from 0.0 to 1.0).
* `distinct_answers`: The number of unique answers (IPs/records) received.

* **SSL**:
### Identity Fields: Who and where
* `identity`: An object containing the primary identifiers of the SSL/TLS session.
* `server_name`: The raw Server Name Indication (SNI) hostname provided by the client.
### Analytical Summaries: The collector's high-level conclusions
* `analysis`: An object containing high-level analytical summaries of the session's security posture.
* `server_reputation`: The reputation of the server_name based on a predefined list and keyword analysis.
* `certificate_status`: A summary of the TLS certificate's validity (e.g., 'Trusted', 'Invalid (Self-Signed)').
* `encryption_strength`: A summary of the encryption quality (e.g., 'Strong', 'Weak (Outdated Protocol)').
* `ja3_threat_match`: A summary indicating if the client's JA3 fingerprint matches a known malicious tool.
* **`ja3s_threat_match`**: A summary indicating if the server's JA3S fingerprint matches a known malicious Command & Control (C2) server.
* `handshake_status`: Indicates whether the TLS handshake was 'Successful' or 'Failed'.
### Numerical Statistics: Raw quantitative data
* `statistics`: An object containing numerical metrics about the session.
* `connection_duration_sec`: The total duration of the connection in seconds.
### Raw Evidence: The detailed, raw data points
* `evidence`: An object containing the raw data points used for analysis.
* `ja3_hash`: The client's raw JA3 fingerprint.
* `ja3s_hash`: The server's raw JA3S fingerprint.
* `tls_version`: The final negotiated TLS version.
* `tls_cipher`: The final negotiated TLS cipher suite.
* **`raw_validation_statuses`**: A **list** of all unique, unparsed validation status strings from the log (e.g., `['ok', 'self-signed certificate']`).
* `certificate_chain_fingerprints`: A list of fingerprints for the certificates in the chain.

* **FILES**: 
### Session-level Analysis: Summary conclusions for the entire event
  * **`analysis`**: An object containing **observational summaries** and a **balanced overall assessment** of the TLS session's security posture.
  * `overall_assessment`: **(Trường quan trọng nhất)** A synthesized, human-readable conclusion that weighs all evidence, including certificate issues and threat intelligence matches. It provides a final, context-aware judgment like `"High Confidence Threat"`, `"Suspicious Anomaly"`, or `"Likely Benign"`.
  * `observed_certificate_issues`: A list of factual issues found with the certificate chain (e.g., `["Self-Signed Certificate", "Expired Certificate"]`). It reports *what was seen* without declaring the entire certificate "Invalid".
  * `observed_weak_protocols`: A list of weak TLS protocol versions observed (e.g., `["TLSv1.0", "SSLv3"]`).
  * `observed_weak_ciphers`: A list of weak cipher suites observed.
  * `handshake_status`: Indicates whether the TLS handshake was 'Successful' or 'Failed'.
### Per-File Evidence: Detailed evidence for each file
* **`evidence`**: An object containing the detailed evidence to support the conclusions above.
* **`findings`**: A list, where each object is a detailed analysis record for a single file (replaces the previous `analyzed_files_summary`).
### Fields within each 'finding' object
Each object in the `findings` list is a flat record containing all information about a single file.
* `type`: The type of finding, always "FileAnalysisFinding" for this collector.
* `fuid`: A unique identifier for the specific file transfer instance.
* `filename`: The original name of the file.
* `direction`: The direction of the file transfer ('Upload' or 'Download').
* `severity`: A categorical assessment of the file's threat level (**Informational**, **Medium**, **High**, **Critical**).
* `risk_score`: A numerical score from 0-100 representing the calculated risk.
* `size_bytes`: The size of the file, in **bytes**.
* `reasons`: A list of standardized keywords explaining **why** the file was flagged (e.g., `MIME_MISMATCH`, `HIGH_ENTROPY`, `SUSPICIOUS_EXTENSION`). This is a critical field for the LLM.
* `hashes`: An object containing the file's cryptographic hashes (md5, sha1).
* `file_type_reported`: The MIME type reported by the protocol (e.g., from an HTTP header).
* `file_type_actual`: The actual MIME type determined by analyzing the file's content (magic number).
* `entropy`: The calculated Shannon entropy of the file, indicating randomness or packing.
* `transfer_status`: The state of the transfer (e.g., "Incomplete (Missing Bytes)").

# GUIDING PRINCIPLES
* **Prioritize High-Confidence Evidence**: Your reasoning should give more weight to specific, reliable indicators over generic or informational ones.
* **Correlate signals**: Explain how different signals from the context support or contradict each other to form a complete picture.
* **Consider Benign Context**: Actively look for signals that explains the suspicious activity as normal behavior. This is key to identifying False Positives.

# TASK & OUTPUT FORMAT
## 1.CORE TASK
Analyze the provided CONTEXT. Your response MUST be a SINGLE, FLAWLESS, and **PERFECTLY VALID JSON object**. Do not include any text outside the JSON.

## 2. OUTPUT SCHEMA
{
  "result": {
    "reasoning": {
      "thought_process": "string", // Step 1 * CRITICAL CHECK: First, check if the 'connection' or 'evidence' objects exist in the CONTEXT. If BOTH are missing, you MUST stop immediately and classify as 'Fasle Positive'. If they exist, proceed to list all signals. Then, identify the most significant signals and formulate a hypothesis."
      "analyze_alert": "string",   // Step 2 * Briefly explain the alert signature's general meaning and purpose.
      "analyze_signals": "string",// Step 3 * Systematically analyze all signals you identified in Step 1: Explain that singals security relevance and explicitly state how it supports or contradicts your stated hypothesis. This process forms a chain of reasoning, analyzing signals into evidence for STEP 4.
      "synthesize_reasoning": "string" // Step 4 * Synthesize all evidence into a chronological narrative. Explain how the event likely occurred from start to finish.
    },
    "conclusion": {
      "classification": "string", // Based on the above analysis. CLASSIFY. Your answer MUST be one of the following two options only: "True Positive" or "False Positive". NO EXPLANATION. DO NOT ADD ANY OTHER WORDS.
      "confidence_score": "number", // Provide a confidence score from 0.0 (very uncertain) to 1.0 (very certain).
      "reasoning_summary": "string" // Provide a brief, one-sentence summary of your final conclusion.
    }
  }
}

## 3. CRITICAL INSTRUCTIONS
Do NOT repeat information between the different reasoning fields. Each field has a unique purpose.
"""

USER_PROMPT = """
**Based on the Persona, Critical Rule, Knowledge Base, and Guiding Principles provided in your system prompt, analyze the following CONTEXT and execute the TASK exactly.**

# CONTEXT
{{ENRICHED_PROMPT}}

"""


# ==============================================================================
# CONFIGURATION * CẤU HÌNH
# ==============================================================================
# Chuyển thành True để gọi API qua ngrok (public), False để gọi API trong mạng nội bộ (local)
USE_REMOTE = True
# --* Cấu hình cho môi trường REMOTE (Ngrok) ---
remote_url = 'https://860c638b6a82.ngrok-free.app/'
REMOTE_API_URL = f"{remote_url}v1/chat/completions"
REMOTE_MODEL_NAME = "meta-llama-3-8b-instruct"


ipv4 = '172.16.11.16'
LOCAL_API_URL = f"http://{ipv4}:8080/v1/chat/completions"
LOCAL_MODEL_NAME = "D:\FPT_CAPSTONE\2025CAPSTONE\1_Source_Code\security_onion_llm_project\llm_model\Meta-Llama-3-8B-Instruct.Q4_K_M.gguf"
    


# Thiết lập logging cơ bản
logging.basicConfig(level=logging.INFO, format='%(asctime)s * %(levelname)s * %(message)s')


class LLMClient:
    def __init__(self):
        """
        Initializes the LLMClient and sets the API configuration based on the USE_REMOTE flag.
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

    def get_classification(self, enriched_prompt: str) -> Dict | None:
        user_prompt = USER_PROMPT.replace("{{ENRICHED_PROMPT}}", enriched_prompt)
        
        logging.info("="*20 + " USER PROMPT " + "="*20)
        logging.info(user_prompt)

        return self._query_llm_api(user_prompt)

    def _query_llm_api(self, user_prompt: str) -> Dict | None:
        """
        Sends a request to the LLM API (local or remote) and returns the result.
        This function is used for both modes.
        """
        headers = {"Content-Type": "application/json"}
        payload = {
            "model": self.model_name,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT },
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
            
            logging.info(f"Response received in {time.monotonic() * start_time:.2f}s:\n{message_content}")
            return self.extract_json(message_content)
            
        except requests.exceptions.RequestException as e:
            logging.error(f"Error calling LLM API at {self.api_url}: {e}", exc_info=True)
            return None
        except Exception as e:
            logging.error(f"An unexpected error occurred: {e}", exc_info=True)
            return None
        
    def extract_json(self, message_content: str) -> dict | None:
        """
        Extracts JSON from a string, prioritizing markdown code blocks.
        **Upgrade:** If the JSON is a list, the function will automatically get the last element.
        """
        json_string = None
        try:
            # Get the JSON content (can be an object or an array)
            match = re.search(r"```(json)?\s*([\[{].*?[\]}])\s*```", message_content, re.DOTALL)
            
            if match:
                # Get the JSON content (can be an object or an array)
                json_string = match.group(2)
            else:
                # If no code block is found, find the first and last JSON characters
                # Improved to find both arrays `[` and objects `{`
                first_char_pos = min(
                    (pos for pos in (message_content.find('{'), message_content.find('[')) if pos != -1),
                    default=-1
                )
                last_char_pos = max(message_content.rfind('}'), message_content.rfind(']'))

                if first_char_pos == -1 or last_char_pos == -1:
                    logging.error("No JSON block or valid JSON characters found in LLM response.")
                    return None
                json_string = message_content[first_char_pos : last_char_pos + 1]

            parsed_data = json.loads(json_string)

        except json.JSONDecodeError as e:
            if not json_string:
                logging.error(f"Failed to extract any potential JSON string. Error: {e}")
                return None
            logging.warning(f"Initial JSON decode failed: {e}. Attempting auto-correction...")
            try:
                repaired_string = repair_json(json_string)
                logging.info("Successfully repaired JSON. Re-parsing the repaired string.")
                parsed_data = json.loads(repaired_string)
            except Exception as final_e:
                logging.error(f"Failed to parse JSON even after repair. Final error: {final_e}")
                logging.error(f"Original faulty content: {json_string}")
                return None
        
        ## =======================================================
        ## LOGIC MỚI ĐỂ XỬ LÝ DANH SÁCH (ARRAY)
        ## =======================================================
        if isinstance(parsed_data, list):
            logging.info("Parsed JSON is a list. Extracting the last element.")
            # Kiểm tra xem danh sách có rỗng không
            if not parsed_data:
                logging.warning("Parsed JSON is an empty list.")
                return None
            
            # Lấy phần tử cuối cùng, giả định đó là kết quả thực tế
            last_item = parsed_data[-1]
            if isinstance(last_item, dict):
                return last_item
            else:
                logging.warning(f"The last item in the JSON list is not a dictionary (type: {type(last_item)}).")
                return None

        elif isinstance(parsed_data, dict):
            # Nếu là dictionary thì đây là trường hợp bình thường
            return parsed_data
        
        else:
            # Xử lý trường hợp JSON hợp lệ nhưng không phải object hay list (ví dụ: "hello", 123)
            logging.warning(f"Parsed JSON is not a dictionary or a list (type: {type(parsed_data)}).")
            return None