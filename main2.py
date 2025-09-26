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
MODE = 'realtime2'
# ----------------------------------------------------

# Determine the alert filename based on the selected MODE
if MODE == 'realtime2':
    # Get the current date, e.g., 'alerts-2025-08-30'
    name_alert = f'alerts-{time.strftime("%Y-%m-%d")}'
else:
    # For 'demo' or 'ground_truth', use the mode name itself
    name_alert = MODE

# --- MODIFICATION 1: Change DIR path to a single FILE path ---
# Dynamically build the required paths based on MODE and name_alert
ALERTS_FILE_PATH = f"./so_alerts/{name_alert}.jsonl"
# This is now a single file to store all enriched prompts
ENRICHED_PROMPTS_FILE_PATH = f"./outputs/enriched_prompts/{MODE}/{MODE}_enriched.jsonl" 
FINAL_ANALYSIS_OUTPUT_PATH = f"./outputs/final_analysis/{MODE}/{MODE}_analysis.jsonl"

# (Optional) Print the configured paths for verification
print(f"✨ Running in MODE: {MODE.upper()}")
print(f"  -> Alert File Path: {ALERTS_FILE_PATH}")
print(f"  -> Enriched Prompts File Path: {ENRICHED_PROMPTS_FILE_PATH}") # Updated print statement
print(f"  -> Final Analysis Path: {FINAL_ANALYSIS_OUTPUT_PATH}")

# Ensure the output directories exist
# Get the directory path from the file paths to ensure they are created
os.makedirs(os.path.dirname(ENRICHED_PROMPTS_FILE_PATH), exist_ok=True)
os.makedirs(os.path.dirname(FINAL_ANALYSIS_OUTPUT_PATH), exist_ok=True)

# --- MODIFICATION 2: Update function to read from a single file ---
def get_next_alert_index(filepath: str) -> int:
    """
    Scans a single JSONL file to find the highest 'alert_index' and returns the next one.
    e.g., if the highest index found is 5, returns 6.
    """
    if not os.path.isfile(filepath):
        return 1 # Start from 1 if the file doesn't exist.

    max_index = 0
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                if line.strip():
                    try:
                        data = json.loads(line)
                        index = data.get('alert_index', 0)
                        if index > max_index:
                            max_index = index
                    except json.JSONDecodeError:
                        # Ignore malformed lines
                        continue
    except (IOError, FileNotFoundError):
        # In case of race condition where file is deleted after os.path.isfile check
        return 1
            
    return max_index + 1

# --- MODIFICATION 3: Update processing function to write to a single file ---
def process_and_write_alert(
        manager: EnrichmentManager, 
        llm_client: LLMClient, 
        alert_row: pd.Series, 
        index: int, 
        final_analysis_file_handle, 
        final_analysis_lock: threading.Lock,
        enriched_prompts_file_handle,
        prompts_lock: threading.Lock
):
    """
    Processes a single alert: enriches, queries LLM, and writes outputs.
    File writing to both output files is protected by separate thread locks.
    """
    try:
        alert = alert_row['original_alert']
        logging.info(f"Worker #{index}: Processing alert...")
        
        # Enrich the alert data to create a detailed prompt.
        enriched_prompt = manager.enrich_and_prompt(alert)
        if not enriched_prompt:
            logging.warning(f"Worker #{index}: Skipping alert, failed to create prompt.")
            return

        # Add the alert_index to the enriched prompt dictionary
        enriched_prompt_with_index = {'alert_index': index, **enriched_prompt}

        # Save the generated prompt to the shared file for auditing.
        try:
            with prompts_lock:
                enriched_prompts_file_handle.write(json.dumps(enriched_prompt_with_index, ensure_ascii=False) + '\n')
                enriched_prompts_file_handle.flush()
            logging.info(f"Worker #{index}: Appended enriched context to {ENRICHED_PROMPTS_FILE_PATH}")
        except IOError as e:
            logging.error(f"Worker #{index}: Failed to write to enriched prompts file. Error: {e}")
        
        # Get LLM analysis.
        llm_analysis_result = None
        
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
            logging.info(f"Worker #{index}: Alert has sufficient evidence. Sending to LLM for deep analysis.")
            if TEST_MODE is True:
                logging.info(f"Worker #{index}: TEST MODE is ON, skipping LLM call.")
                llm_analysis_result = {
                    "summary": "This is a test result.",
                }
            else:
                logging.info(f"Worker #{index}: Sending request to LLM...")  
                # Convert prompt to a compact JSON string for the API call.
                prompt_as_json_string = json.dumps(enriched_prompt)
                
                start_llm = time.monotonic()
                llm_analysis_result = llm_client.get_classification(prompt_as_json_string)
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
            # Reference the single file where the prompt is stored
            "source_enrichment_file": ENRICHED_PROMPTS_FILE_PATH, 
            "llm_analysis": llm_analysis_result
        }
        
        # Write the result to the final analysis file
        with final_analysis_lock:
            final_analysis_file_handle.write(json.dumps(output_record) + '\n')
            final_analysis_file_handle.flush() 
            logging.info(f"Worker #{index}: Wrote analysis to output file.")

    except Exception:
        logging.error(f"Worker #{index}: An unexpected error occurred while processing alert.", exc_info=True)


# --- MODIFICATION 4: Update main function to handle the single file ---
def main():
    """    
    Main function to monitor an alert file and process new entries.
    """
    logging.info(f"--- STARTING ALERT MONITORING SERVICE FOR: {ALERTS_FILE_PATH} ---")
    logging.info("Press Ctrl+C to stop the service.")

    # These directories are already created at the top level
    
    manager = EnrichmentManager()
    llm_client = LLMClient()
    final_analysis_lock = threading.Lock() 
    prompts_lock = threading.Lock() # A separate lock for the prompts file
    
    # Define file handles outside the try block for the finally block to access them
    input_file = None
    final_output_file = None
    enriched_prompts_file = None
    executor = None

    try:
        # Open all required files and the thread pool
        input_file = open(ALERTS_FILE_PATH, 'r', encoding='utf-8')
        final_output_file = open(FINAL_ANALYSIS_OUTPUT_PATH, 'a', encoding='utf-8')
        enriched_prompts_file = open(ENRICHED_PROMPTS_FILE_PATH, 'a', encoding='utf-8')
        executor = ThreadPoolExecutor(max_workers=MAX_WORKERS, thread_name_prefix='Worker')

        logging.info("Log file opened, seeking to end to monitor for new alerts...")
        input_file.seek(0, 2)  # Move to the end of the file.
        
        # Get the starting alert index from our single prompts file
        alert_counter = get_next_alert_index(ENRICHED_PROMPTS_FILE_PATH)
        logging.info(f"Starting alert counter at index: {alert_counter}")
        
        # Continuously read for new lines.
        while True:
            line = input_file.readline()
            if not line:
                time.sleep(1) 
                continue

            try:
                # Parse the new line as a JSON object into a DataFrame.
                new_alerts_df = pd.read_json(line, lines=True)
                for _, alert_row in new_alerts_df.iterrows():
                    logging.info(f"New alert #{alert_counter} detected. Submitting for processing...")
                    executor.submit(
                        process_and_write_alert,
                        manager, 
                        llm_client, 
                        alert_row, 
                        alert_counter,
                        final_output_file, 
                        final_analysis_lock,
                        enriched_prompts_file,
                        prompts_lock
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
        if executor:
            executor.shutdown(wait=True)
            logging.info("Closed ThreadPoolExecutor.")
        if input_file and not input_file.closed:
            input_file.close()
        if final_output_file and not final_output_file.closed:
            final_output_file.close()
        if enriched_prompts_file and not enriched_prompts_file.closed:
            enriched_prompts_file.close()
        logging.info("---SERVICE SHUTDOWN COMPLETE ---")


if __name__ == "__main__":
    main()