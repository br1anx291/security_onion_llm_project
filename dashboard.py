import streamlit as st
import json
import pandas as pd
import math
import os
import time

# --- Page and Mode Configuration ---
st.set_page_config(layout="wide", page_title="LLM Alert Triage")

# --- ONLY CHANGE THIS VARIABLE TO SWITCH MODES ---
# Valid values: 'realtime', 'demo', 'ground_truth'
MODE = 'demo'
# ----------------------------------------------------

# Configuration dictionary for different modes
CONFIGS = {
    'realtime': {
        'sub_dir': 'realtime',
        'alert_name_pattern': f'alerts_all-{time.strftime("%Y-%m-%d")}'
    },
    'demo': {
        'sub_dir': 'demo',
        'alert_name_pattern': 'demo'
    },
    'ground_truth': {
        'sub_dir': 'ground_truth',
        'alert_name_pattern': 'ground_truth'
    }
}

# Select and build paths based on the chosen MODE
try:
    selected_config = CONFIGS[MODE]
    name_alert = selected_config['alert_name_pattern']
    sub_dir = selected_config['sub_dir']
except KeyError:
    raise ValueError(f"Invalid MODE '{MODE}'. Please choose from: {list(CONFIGS.keys())}")

OUTPUTS_BASE_DIR = "./outputs"
RAW_ALERTS_FILE = f"./so_alerts/{name_alert}.jsonl"
FINAL_ANALYSIS_DIR = f"{OUTPUTS_BASE_DIR}/final_analysis/{sub_dir}"
ENRICHED_PROMPTS_DIR = f"{OUTPUTS_BASE_DIR}/enriched_prompts/{sub_dir}"
LLM_ANALYSIS_FILE = f"{FINAL_ANALYSIS_DIR}/{name_alert}_analysis.jsonl"
CONTEXT_FOLDER = ENRICHED_PROMPTS_DIR

# Check if the main analysis file exists to control UI elements
ANALYSIS_FILE_EXISTS = os.path.exists(LLM_ANALYSIS_FILE)
ITEMS_PER_PAGE = 20

# --- Initialize Session State ---
if 'expanded_alert_id' not in st.session_state:
    st.session_state.expanded_alert_id = None
if 'sidebar_details' not in st.session_state:
    st.session_state.sidebar_details = {"active_alert_id": None, "context_data": None, "llm_data": None}
if 'current_page' not in st.session_state:
    st.session_state.current_page = 1

# --- Data Handling Functions ---
def get_nested_value(d, path, default="N/A"):
    """Safely retrieve a value from a nested dict using a dot-separated path."""
    if path in d: # Prioritize flat keys first
        return d.get(path, default)

    keys = path.split('.')
    val = d
    for key in keys:
        if isinstance(val, dict):
            val = val.get(key)
            if val is None:
                return default
        else:
            return default
    return val if val is not None else default

@st.cache_data
def load_and_merge_data(raw_file, analysis_file):
    """Loads raw alerts and merges them with LLM analysis results."""
    try:
        with open(raw_file, 'r', encoding='utf-8') as f:
            raw_list = [json.loads(line) for line in f if line.strip()]
    except Exception as e:
        st.error(f"Error reading raw alerts file: {e}")
        return None

    llm_dict = {}
    try:
        with open(analysis_file, 'r', encoding='utf-8') as f:
            llm_list = [json.loads(line) for line in f if line.strip()]
        # Create a dictionary for quick lookups using alert_index
        llm_dict = {item['alert_index'] - 1: item for item in llm_list if 'alert_index' in item}
    except FileNotFoundError:
        st.toast(f"Analysis file not found. Verdicts will be 'Pending'.")
    except Exception as e:
        st.error(f"Error reading analysis file: {e}")

    merged = []
    for index, alert in enumerate(raw_list):
        analysis = llm_dict.get(index, {})
        uid = f"{get_nested_value(alert, '@timestamp')}-{index}"
        merged.append({
            "unique_id": uid, "alert_index": index,
            "timestamp": get_nested_value(alert, "@timestamp"),
            "alert_name": get_nested_value(alert, "rule.name"),
            "source_ip": get_nested_value(alert, "source.ip"),
            "source_port": get_nested_value(alert, "source.port"),
            "dest_ip": get_nested_value(alert, "destination.ip"),
            "dest_port": get_nested_value(alert, "destination.port"),
            "llm_verdict": get_nested_value(analysis, "llm_analysis.result.conclusion.classification", "Pending"),
            "reasoning_summary": get_nested_value(analysis, "llm_analysis.result.conclusion.reasoning_summary", "No summary available."),
            "llm_result_json": get_nested_value(analysis, "llm_analysis.result", {"status": "Pending Analysis"})
        })

    # Sort alerts by index for ground_truth, otherwise by timestamp
    if MODE == 'ground_truth':
        merged.sort(key=lambda x: x['alert_index'])
    else:
        merged.sort(key=lambda x: x['alert_index'], reverse=True)
    return merged

# --- UI Callback Functions ---
def show_context_details(alert_id, alert_index):
    """Callback to display context details in the sidebar."""
    st.session_state.sidebar_details["active_alert_id"] = alert_id
    st.session_state.sidebar_details["llm_data"] = None # Clear LLM details

    if not ANALYSIS_FILE_EXISTS:
        st.session_state.sidebar_details["context_data"] = {
            "status": "Pending Analysis",
            "detail": "Context data is available only after the full analysis is complete."
        }
        return

    try:
        filepath = os.path.join(CONTEXT_FOLDER, f"alert_enrichment_{alert_index + 1}.jsonl")
        with open(filepath, 'r', encoding='utf-8') as f:
            st.session_state.sidebar_details["context_data"] = json.load(f)
    except Exception as e:
        st.session_state.sidebar_details["context_data"] = {"error": f"Could not load context file: {e}"}

def show_llm_details(alert_id, llm_json):
    """Callback to display LLM analysis details in the sidebar."""
    st.session_state.sidebar_details["active_alert_id"] = alert_id
    st.session_state.sidebar_details["context_data"] = None # Clear context details
    st.session_state.sidebar_details["llm_data"] = llm_json

# --- UI Display Functions ---
def display_grid_header():
    """Renders the header row for the alerts grid."""
    cols = st.columns((1, 2.4, 3.6, 2, 0.9, 2, 1, 2.1))
    headers = ["", "Timestamp", "Alert Name", "Source IP", "Port", "Destination IP", "Port", "LLM Verdict"]
    for col, h in zip(cols, headers):
        col.markdown(f"**{h}**")
    st.divider()

def toggle_expand(alert_id):
    """Expands or collapses the details section of an alert row."""
    current_expanded = st.session_state.expanded_alert_id
    st.session_state.expanded_alert_id = None if current_expanded == alert_id else alert_id

def display_alert_row(alert):
    """Renders a single alert row and its expandable details section."""
    is_expanded = (st.session_state.expanded_alert_id == alert['unique_id'])

    with st.container(border=True):
        row_cols = st.columns((0.8, 2.5, 3.7, 2, 1, 2, 0.9, 2.1))

        # Row content
        button_char = "🔽" if is_expanded else "▶️"
        row_cols[0].button(button_char, key=f"expand_{alert['unique_id']}", on_click=toggle_expand, args=(alert['unique_id'],))
        try:
            ts = pd.to_datetime(alert['timestamp']).strftime('%Y-%m-%d %H:%M:%S')
        except (pd.errors.ParserError, TypeError):
            ts = alert['timestamp']
        row_cols[1].write(ts)
        row_cols[2].write(alert["alert_name"])
        row_cols[3].write(alert["source_ip"])
        row_cols[4].write(str(alert["source_port"]))
        row_cols[5].write(alert["dest_ip"])
        row_cols[6].write(str(alert["dest_port"]))

        # Verdict with color coding
        verdict = alert["llm_verdict"]
        with row_cols[7]:
            if verdict == "True Positive": st.error(verdict)
            elif verdict == "False Positive": st.success(verdict)
            else: st.warning(verdict)

        # Expanded section with details
        if is_expanded:
            st.markdown("---")
            summary_col, button_col = st.columns((3.2, 0.8))
            summary_col.markdown("**Reasoning Summary:**")
            summary_col.info(alert['reasoning_summary'])
            
            with button_col:
                st.markdown("**Details**")
                st.button("📄 Context", key=f"context_{alert['unique_id']}", on_click=show_context_details, args=(alert['unique_id'], alert['alert_index']), use_container_width=True)
                st.button("🔬 LLM", key=f"details_{alert['unique_id']}", on_click=show_llm_details, args=(alert['unique_id'], alert['llm_result_json']), use_container_width=True)

# --- Main App Layout ---
st.markdown("""
<style>
    button[data-testid="baseButton-secondary"] { background-color: transparent; border: none; padding-left: 0 !important; }
    hr { margin: 2px 0px !important; }
</style>
""", unsafe_allow_html=True)

st.title("🛡️ LLM Alert Triage")

# --- Sidebar ---
with st.sidebar:
    st.header("🔍 Filters")
    search_query = st.text_input("Search by Alert Name or IP:")
    verdict_options = ["All", "True Positive", "False Positive", "Unable to Determine", "Pending"]
    verdict_filter = st.selectbox("Filter by LLM Verdict:", verdict_options)
    st.divider()

    st.header("⚙️ Controls")
    if st.button("🔄 Refresh Now", use_container_width=True):
        st.cache_data.clear()
        st.rerun()

    auto_refresh = st.toggle("Enable Auto-Refresh", value=False)
    refresh_interval = 5
    if auto_refresh:
        refresh_interval = st.selectbox("Interval (seconds):", options=[5, 10, 15, 20], index=0)

    st.divider()

    # --- Details Display Area in Sidebar ---
    details = st.session_state.sidebar_details
    if details["context_data"] or details["llm_data"]:
        if details["context_data"]:
            st.header("📄 Context Details")
            st.json(details["context_data"], expanded=True)
        if details["llm_data"]:
            st.header("🔬 LLM Details")
            st.json(details["llm_data"], expanded=True)

        st.divider()
        if st.button("Close Details"):
            st.session_state.sidebar_details = {"active_alert_id": None, "context_data": None, "llm_data": None}
            st.rerun()

# --- Main Content Area ---
all_alerts = load_and_merge_data(RAW_ALERTS_FILE, LLM_ANALYSIS_FILE)

if all_alerts:
    # Apply filters
    filtered_alerts = all_alerts
    if search_query:
        sq = search_query.lower()
        filtered_alerts = [a for a in filtered_alerts if sq in str(a['alert_name']).lower() or sq in str(a['source_ip']) or sq in str(a['dest_ip'])]
    if verdict_filter != "All":
        filtered_alerts = [a for a in filtered_alerts if a['llm_verdict'] == verdict_filter]

    # Pagination logic
    total_alerts = len(filtered_alerts)
    total_pages = math.ceil(total_alerts / ITEMS_PER_PAGE) if total_alerts > 0 else 1
    st.session_state.current_page = min(st.session_state.current_page, total_pages)
    
    start_idx = (st.session_state.current_page - 1) * ITEMS_PER_PAGE
    end_idx = start_idx + ITEMS_PER_PAGE
    paginated_alerts = filtered_alerts[start_idx:end_idx]

    # Pagination controls
    info_col, prev_col, page_col, next_col = st.columns([5.5, 2, 2.5, 2])
    info_col.info(f"Displaying **{len(paginated_alerts)}** of **{total_alerts}** matching alerts.")
    if prev_col.button("⬅️ Previous", use_container_width=True, disabled=(st.session_state.current_page <= 1)):
        st.session_state.current_page -= 1
        st.rerun()
    page_col.write(f"<div style='text-align: center; padding-top: 0.5rem;'>Page <b>{st.session_state.current_page}</b> of <b>{total_pages}</b></div>", unsafe_allow_html=True)
    if next_col.button("Next ➡️", use_container_width=True, disabled=(st.session_state.current_page >= total_pages)):
        st.session_state.current_page += 1
        st.rerun()

    # Display alerts grid
    display_grid_header()
    for alert in paginated_alerts:
        display_alert_row(alert)
else:
    st.warning("Could not load alert data. Check if the raw alerts file exists and is not empty.")

# Auto-refresh logic at the end of the script
if auto_refresh:
    time.sleep(refresh_interval)
    st.rerun()