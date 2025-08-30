# security_onion_llm_project/main.py


import json
import logging
import threading
import os
import time
import pandas as pd
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from typing import Dict, Any
from enrichment_manager import EnrichmentManager
from llm_client import LLMClient

# --- Configuration ---
# 1. Logging Setup
LOG_FORMAT = "%(asctime)s [%(threadName)-12.12s] [%(levelname)-5.5s]  %(message)s"
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)

# 2. General Settings
MAX_WORKERS = 10
TEST_MODE = False

# --- ONLY CHANGE THIS VARIABLE TO SWITCH MODES ---
# Valid values: 'realtime', 'demo', 'ground_truth'
MODE = 'demo'
# ----------------------------------------------------

# Determine the alert filename based on the selected MODE
if MODE == 'realtime':
    # Get the current date, e.g., 'alerts-2025-08-30'
    name_alert = f'alerts-{time.strftime("%Y-%m-%d")}'
else:
    # For 'demo' or 'ground_truth', use the mode name itself
    name_alert = MODE

# Dynamically build the required paths based on MODE and name_alert
ALERTS_FILE_PATH = f"./so_alerts/{name_alert}.jsonl"
ENRICHED_PROMPTS_DIR = f"./outputs/enriched_prompts/{MODE}"
FINAL_ANALYSIS_OUTPUT_PATH = f"./outputs/final_analysis/{MODE}/{name_alert}_analysis.jsonl"

# (Optional) Print the configured paths for verification
print(f"✨ Running in MODE: {MODE.upper()}")
print(f"  -> Alert File Path: {ALERTS_FILE_PATH}")
print(f"  -> Enriched Prompts Dir: {ENRICHED_PROMPTS_DIR}")
print(f"  -> Final Analysis Path: {FINAL_ANALYSIS_OUTPUT_PATH}")

# Ensure the output directories exist
os.makedirs(ENRICHED_PROMPTS_DIR, exist_ok=True)
# Get the directory path from the final output file to ensure it's created
final_dir = os.path.dirname(FINAL_ANALYSIS_OUTPUT_PATH)
os.makedirs(final_dir, exist_ok=True)



def get_next_alert_index(directory: str) -> int:
    """
    Scans a directory to find the highest enrichment file index and returns the next one.
    e.g., if 'alert_enrichment_5.jsonl' is the highest, returns 6.
    """
    if not os.path.isdir(directory):
        return 1 # Start from 1 if the directory doesn't exist.

    max_index = 0
    prefix = 'alert_enrichment_'
    suffix = '.jsonl'

    for filename in os.listdir(directory):
        if filename.startswith(prefix) and filename.endswith(suffix):
            try:
                num_str = filename[len(prefix):-len(suffix)]
                index = int(num_str)
                if index > max_index:
                    max_index = index
            except ValueError:
                # Ignore files with non-integer indices.
                continue
                
    return max_index + 1

def process_and_write_alert(
        manager: EnrichmentManager, llm_client: LLMClient, alert_row: pd.Series, index: int, 
    output_file_handle, lock: threading.Lock
):
    """
    Processes a single alert: enriches, queries LLM, and writes the analysis.
    File writing is protected by a thread lock.
    """
    try:
        alert = alert_row['original_alert']
        logging.info(f"Worker #{index}: Processing alert...")
        
        # Enrich the alert data to create a detailed prompt.
        enriched_prompt = manager.enrich_and_prompt(alert)
        if not enriched_prompt:
            logging.warning(f"Worker #{index}: Skipping alert, failed to create prompt.")
            return

        pretty_prompt = json.dumps(enriched_prompt, indent=2, ensure_ascii=False)
        logging.info(f"Worker #{index}: Created enriched prompt:\n{pretty_prompt}")

        # Save the generated prompt to its own file for auditing.
        prompt_output_path = os.path.join(ENRICHED_PROMPTS_DIR, f"alert_enrichment_{index}.jsonl")

        try:
            os.makedirs(ENRICHED_PROMPTS_DIR, exist_ok=True)
            with open(prompt_output_path, 'w', encoding='utf-8') as f_prompt:
                json.dump(enriched_prompt, f_prompt, indent=4, ensure_ascii=False)
            logging.info(f"Worker #{index}: Saved enriched prompt to {prompt_output_path}")
        except IOError as e:
            logging.error(f"Worker #{index}: Failed to save prompt file. Error: {e}")
        
        prompt_as_json_string = json.dumps(enriched_prompt) # Không cần indent khi gửi cho LLM
        
         # Get LLM analysis.
        llm_analysis_result  = None
        
        # If no evidence is found, classify as False Positive without calling the LLM.
        if 'connection' not in enriched_prompt and 'evidence' not in enriched_prompt:
            logging.warning(f"Worker #{index}: Alert lacks 'connection' and 'evidence'. Auto-classifying as False Positive.")
            
            alert_name = alert.get('rule', {}).get('name', 'N/A')
            llm_analysis_result = {
                "result": {
                    "reasoning": {
                        "thought_process": "Initial check: The context is missing the 'connection' and/or 'evidence' objects. As per CRITICAL RULE #3, without corroborating signals, the alert must be classified as 'False Positive'. Bypassing full analysis.",
                        "analyze_alert": f"The alert signature '{alert_name}' suggests a potential threat, but this is only a claim that requires corroboration.",
                        "analyze_signals": "No corroborating signals were found. Neither connection details nor specific evidence (HTTP, DNS, etc.) could be retrieved for this event.",
                        "synthesize_reasoning": "The event triggered an alert, but a search for contextual data yielded no supporting evidence. The activity is therefore considered unproven and benign by definition."
                    },
                    "conclusion": {
                        "classification": "False Positive",
                        "confidence_score": 1.0,
                        "reasoning_summary": "Classified as False Positive due to a complete lack of corroborating evidence from network logs."
                    }
                }
            }
        else:
            logging.info(f"Worker #{index}: Alert có đủ bằng chứng. Gửi đến LLM để phân tích sâu.")
            if TEST_MODE is True:
                logging.info(f"Worker #{index}: TEST MODE is ON, skipping LLM call.")
                llm_analysis_result  = {
                    "summary": "This is a test result.",
                }
            else:
                logging.info(f"Worker #{index}: Sending request to LLM...")  
                # Convert prompt to a compact JSON string for the API call.
                prompt_as_json_string = json.dumps(enriched_prompt)    
                 
                start_llm = time.monotonic()
                llm_analysis_result  = llm_client.get_classification(prompt_as_json_string)
                end_llm = time.monotonic()
            
                if not llm_analysis_result:
                    logging.error(f"Worker #{index}: LLM returned an invalid result.")
                    return
            
                logging.info(f"Worker #{index}: LLM inference took {end_llm - start_llm:.2f} seconds.")

        # Assemble the final output record.
        output_record = {
            "alert_index": index,
            "processed_at": datetime.now().isoformat(),
            "original_alert_signature": alert.get('rule', {}).get('name', 'N/A'),
            "enriched_prompt_file": prompt_output_path, 
            "llm_analysis": llm_analysis_result
        }
        
        # 4. Ghi kết quả vào file
        with lock:
            output_file_handle.write(json.dumps(output_record) + '\n')
            output_file_handle.flush() 
            logging.info(f"Worker #{index}: Wrote analysis to output file.")

    except Exception:
        logging.error(f"Worker #{index}: An unexpected error occurred while processing alert.", exc_info=True)


def main():
    """    
    Main function to monitor an alert file and process new entries.
    """
    logging.info(f"--- STARTING ALERT MONITORING SERVICE FOR: {ALERTS_FILE_PATH} ---")
    logging.info("Press Ctrl+C to stop the service.")

    # Ensure output directories exist before starting.
    os.makedirs(ENRICHED_PROMPTS_DIR, exist_ok=True)
    os.makedirs(os.path.dirname(FINAL_ANALYSIS_OUTPUT_PATH), exist_ok=True)
    
    manager = EnrichmentManager()
    llm_client = LLMClient()
    lock = threading.Lock() 
    
    try:
        with open(ALERTS_FILE_PATH, 'r', encoding='utf-8') as input_file, \
             open(FINAL_ANALYSIS_OUTPUT_PATH, 'a', encoding='utf-8') as output_file, \
             ThreadPoolExecutor(max_workers=MAX_WORKERS, thread_name_prefix='Worker') as executor:
            
            logging.info("Log file opened, seeking to end to monitor for new alerts...")
            input_file.seek(0, 2)  # Move to the end of the file.
            
            alert_counter = get_next_alert_index(ENRICHED_PROMPTS_DIR)
            
            # Continuously read for new lines.
            while True:
                line = input_file.readline()
                if not line:
                    time.sleep(1) 
                    continue

                try:
                    # Parse the new line as a JSON object into a DataFrame.
                    new_alerts_df = pd.read_json(line, lines=True)
                    for index, alert_row in new_alerts_df.iterrows():
                        logging.info(f"New alert #{alert_counter} detected. Submitting for processing...")
                        executor.submit(
                            process_and_write_alert,
                            manager, llm_client, alert_row, alert_counter,
                            output_file, lock
                        )
                        alert_counter += 1

                except (json.JSONDecodeError, ValueError):
                    logging.warning(f"Skipping invalid line: {line.strip()}")
                    
    except FileNotFoundError:
        logging.error(f"Error: Log file '{ALERTS_FILE_PATH}' not found. Please create it before running.")
    except KeyboardInterrupt:
        logging.info("--- SHUTDOWN SIGNAL RECEIVED (Ctrl+C). STOPPING SERVICE. ---")
    except Exception as e:
        logging.error(f"A critical error occurred: {e}", exc_info=True)
    finally:
        if 'executor' in locals() and executor:
            executor.shutdown(wait=True)
            logging.info("Closed ThreadPoolExecutor.")
        if 'input_file' in locals() and not input_file.closed:
            input_file.close()
        if 'output_file' in locals() and not output_file.closed:
            output_file.close()
        logging.info("---SERVICE SHUTDOWN COMPLETE ---")


if __name__ == "__main__":
    main()