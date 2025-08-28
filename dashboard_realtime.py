import streamlit as st
import json
import pandas as pd
import math
import os
import time
# import streamlit.components.v1 as components

# --- CẤU HÌNH & HẰNG SỐ ---
st.set_page_config(layout="wide", page_title="Robust Alert Triage")
name_alert = f'alerts_all-{time.strftime("%Y-%m-%d")}'
# name_alert = f'alerts_all-2025-08-13'
RAW_ALERTS_FILE = f"./so_alerts/{name_alert}.jsonl"
OUTPUTS_BASE_DIR = "./outputs"
FINAL_ANALYSIS_DIR = f"{OUTPUTS_BASE_DIR}/final_analysis"
ENRICHED_PROMPTS_DIR = f"{OUTPUTS_BASE_DIR}/enriched_prompts/realtime/"

LLM_ANALYSIS_FILE = f"./{FINAL_ANALYSIS_DIR}/realtime/{name_alert}_analysis.jsonl"
CONTEXT_FOLDER = ENRICHED_PROMPTS_DIR

# ★★★ THAY ĐỔI 1: KIỂM TRA SỰ TỒN TẠI CỦA FILE PHÂN TÍCH CHÍNH ★★★
# Biến này sẽ là 'True' nếu vòng phân tích đã hoàn tất, ngược lại là 'False'.
ANALYSIS_FILE_EXISTS = os.path.exists(LLM_ANALYSIS_FILE)

ITEMS_PER_PAGE = 30
# --- KHỞI TẠO SESSION STATE ---
if 'expanded_alert_id' not in st.session_state: st.session_state.expanded_alert_id = None
if 'sidebar_details' not in st.session_state:
    st.session_state.sidebar_details = {
        "active_alert_id": None,
        "context_data": None,
        "llm_data": None
    }
if 'current_page' not in st.session_state: st.session_state.current_page = 1

# --- HÀM XỬ LÝ DỮ LIỆU ---
def get_nested_value(d, path, default="N/A"):
    keys = path.split('.')
    for key in keys:
        if isinstance(d, dict): d = d.get(key, default)
        else: return default
    return d

@st.cache_data
def load_and_merge_data(raw_file, analysis_file):
    try:
        with open(raw_file, 'r', encoding='utf-8') as f:
            raw_list = [json.loads(line) for line in f if line.strip()]
    except Exception as e:
        st.error(f"Error reading raw alerts file: {e}")
        return None
    try:
        with open(analysis_file, 'r', encoding='utf-8') as f:
            llm_list = [json.loads(line) for line in f if line.strip()]
        llm_dict = {item['alert_index']: item for item in llm_list if 'alert_index' in item}
    except Exception:
        llm_dict = {}

    merged = []
    for index, alert in enumerate(raw_list):
        analysis = llm_dict.get(index, {})
        uid = f"{get_nested_value(alert, '@timestamp')}-{index}"
        merged.append({
            "unique_id": uid, "alert_index": index, "timestamp": get_nested_value(alert, "@timestamp"),
            "alert_name": get_nested_value(alert, "rule.name"), "source_ip": get_nested_value(alert, "source.ip"),
            "source_port": get_nested_value(alert, "source.port"), "dest_ip": get_nested_value(alert, "destination.ip"),
            "dest_port": get_nested_value(alert, "destination.port"),
            "llm_verdict": get_nested_value(analysis, "llm_analysis.result.conclusion.classification", "Pending"),
            "reasoning_summary": get_nested_value(analysis, "llm_analysis.result.conclusion.reasoning_summary", "No summary."),
            "llm_result_json": get_nested_value(analysis, "llm_analysis.result", {"status": "Pending Analysis"})
        })
    return merged

# ★★★ THAY ĐỔI 2: CẬP NHẬT HÀM `show_context_details` ★★★
def show_context_details(alert_id, alert_index):
    """Callback: Hiển thị chi tiết Context, có kiểm tra alert đang hoạt động và trạng thái hoàn thành."""
    if st.session_state.sidebar_details["active_alert_id"] != alert_id:
        st.session_state.sidebar_details = {
            "active_alert_id": alert_id, "context_data": None, "llm_data": None
        }

    # Nếu file phân tích tổng hợp chưa tồn tại, nghĩa là vòng xử lý chưa xong.
    # Không đọc file context cũ, thay vào đó hiển thị trạng thái chờ.
    if not ANALYSIS_FILE_EXISTS:
        st.session_state.sidebar_details["context_data"] = {
            "status": "Pending Analysis",
            "detail": "Context data is available only after the full analysis round is complete."
        }
        return # Dừng hàm tại đây để tránh đọc file cũ

    # Nếu file phân tích đã tồn tại, tiến hành đọc file context như bình thường.
    try:
        file_number = alert_index + 1
        filepath = os.path.join(CONTEXT_FOLDER, f"alert_enrichment_{file_number}.jsonl")
        with open(filepath, 'r', encoding='utf-8') as f:
            context_data = json.load(f)
        st.session_state.sidebar_details["context_data"] = context_data
    except Exception as e:
        st.session_state.sidebar_details["context_data"] = {"error": f"Could not load context file: {e}"}

def show_llm_details(alert_id, llm_json):
    """Callback: Hiển thị chi tiết LLM, có kiểm tra alert đang hoạt động."""
    if st.session_state.sidebar_details["active_alert_id"] != alert_id:
        st.session_state.sidebar_details = {
            "active_alert_id": alert_id, "context_data": None, "llm_data": None
        }
    st.session_state.sidebar_details["llm_data"] = llm_json

# --- HÀM VẼ GIAO DIỆN ---
def display_grid_header():
    cols = st.columns((1, 2.4, 3.6, 2, 0.9, 2, 1, 2.1))
    headers = ["", "Timestamp", "Alert Name", "Source IP", "Port", "Destination IP", "Port", "LLM Verdict"]
    for col, h in zip(cols, headers): col.markdown(f"**{h}**")
    st.divider()

def toggle_expand(alert_id):
    st.session_state.expanded_alert_id = None if st.session_state.expanded_alert_id == alert_id else alert_id

def display_alert_row(alert):
    is_expanded = (st.session_state.expanded_alert_id == alert['unique_id'])
    
    with st.container(border=True):
        row_cols = st.columns((0.8, 2.5, 3.7, 2, 1, 2, 0.9, 2.1))
        
        button_char = "🔽" if is_expanded else "▶️"
        row_cols[0].button(button_char, key=f"expand_{alert['unique_id']}", on_click=toggle_expand, args=(alert['unique_id'],))
        
        try: ts = pd.to_datetime(alert['timestamp']).strftime('%Y-%m-%d %H:%M:%S')
        except: ts = alert['timestamp']
            
        row_cols[1].write(ts)
        row_cols[2].write(alert["alert_name"])
        row_cols[3].write(alert["source_ip"])
        row_cols[4].write(str(alert["source_port"]))
        row_cols[5].write(alert["dest_ip"])
        row_cols[6].write(str(alert["dest_port"]))
        
        verdict = alert["llm_verdict"]
        with row_cols[7]:
            if verdict == "True Positive": st.error(verdict)
            elif verdict == "False Positive": st.success(verdict)
            else: st.warning(verdict)
        
        if is_expanded:
            st.markdown("---")
            summary_col, button_col = st.columns((3.2, 0.8))
            with summary_col:
                st.markdown("**Reasoning Summary:**")
                st.info(alert['reasoning_summary'])
            with button_col:
                st.markdown("**Details**")
                button_col.button(
                    "📄Context Details", key=f"context_{alert['unique_id']}",
                    on_click=show_context_details, args=(alert['unique_id'], alert['alert_index']),
                    use_container_width=True
                )
                button_col.button(
                    "🔬LLM Details", key=f"details_{alert['unique_id']}",
                    on_click=show_llm_details, args=(alert['unique_id'], alert['llm_result_json']),
                    use_container_width=True
                )

# --- GIAO DIỆN CHÍNH ---
st.markdown("""
<style>
    button[data-testid="baseButton-secondary"] { background-color: transparent; border: none; padding-left: 0 !important; }
    hr { margin: 2px 0px !important; }
</style>
""", unsafe_allow_html=True)

st.title("🛡️ LLM Alert Triage")

# --- BẮT ĐẦU THAY ĐỔI ---

# Sidebar
with st.sidebar:
    st.header("🔍 Filters")
    search_query = st.text_input("Search by Alert Name or IP:")
    verdict_options = ["All", "True Positive", "False Positive", "Unable to Determine", "Pending"]
    verdict_filter = st.selectbox("Filter by LLM Verdict:", verdict_options)
    st.divider()

    st.header("⚙️ Refresh Controls")
    # Nút Refresh được chuyển vào đây
    if st.button("🔄 Refresh Now", use_container_width=True):
        st.cache_data.clear()
        st.rerun()

    # auto_refresh = st.toggle("Enable Auto-Refresh", value=False)
    # if auto_refresh:
    #     refresh_interval = st.selectbox("Refresh Interval (seconds):", options=[5, 10, 15, 20], index=0)
    # else:
    #     refresh_interval = 5 # Giá trị mặc định khi không bật auto-refresh
    
    st.divider()

    # Phần hiển thị chi tiết trong sidebar
    details = st.session_state.sidebar_details
    if details["context_data"] or details["llm_data"]:
        if details["context_data"]:
            st.header("📄Context Details")
            st.json(details["context_data"])
            st.markdown("---")
            
        if details["llm_data"]:
            st.header("🔬LLM Details")
            st.json(details["llm_data"])
            st.markdown("---")

        if st.button("Close All Details"):
            st.session_state.sidebar_details = {
                "active_alert_id": None, "context_data": None, "llm_data": None
            }
            st.rerun()

# --- KẾT THÚC THAY ĐỔI ---

all_alerts = load_and_merge_data(RAW_ALERTS_FILE, LLM_ANALYSIS_FILE)

if all_alerts:
    # Lọc dữ liệu
    filtered_alerts = all_alerts
    if search_query:
        sq = search_query.lower()
        filtered_alerts = [a for a in filtered_alerts if sq in str(a['alert_name']).lower() or sq in str(a['source_ip']) or sq in str(a['dest_ip'])]
    if verdict_filter != "All":
        filtered_alerts = [a for a in filtered_alerts if a['llm_verdict'] == verdict_filter]

    # Phân trang
    total_alerts = len(filtered_alerts)
    total_pages = math.ceil(total_alerts / ITEMS_PER_PAGE) if total_alerts > 0 else 1
    if st.session_state.current_page > total_pages:
        st.session_state.current_page = total_pages
        
    start_idx = (st.session_state.current_page - 1) * ITEMS_PER_PAGE
    end_idx = start_idx + ITEMS_PER_PAGE
    paginated_alerts = filtered_alerts[start_idx:end_idx]
    
    # Xóa cột chứa nút Refresh cũ khỏi giao diện chính
    info_col, p_col1, p_col2, p_col3 = st.columns([5.5, 2, 2.5, 2]) # Điều chỉnh lại cột
    info_col.info(f"Displaying **{len(paginated_alerts)}** of **{total_alerts}** matching alerts.")
    if p_col1.button("⬅️ Previous", key="prev_page", use_container_width=True, disabled=(st.session_state.current_page <= 1)):
        st.session_state.current_page -= 1
        st.rerun()
    p_col2.write(f"\n\n Page **{st.session_state.current_page}** of **{total_pages}**")
    if p_col3.button("Next ➡️", key="next_page", use_container_width=True, disabled=(st.session_state.current_page >= total_pages)):
        st.session_state.current_page += 1
        st.rerun()
    
    display_grid_header()
    for alert in paginated_alerts:
        display_alert_row(alert)
else:
    st.warning("Could not load alert data.")

# # Logic auto-refresh ở cuối script
# if auto_refresh:
#     # Nhúng một đoạn mã HTML vô hình vào trang.
#     # Thẻ <meta http-equiv="refresh"> sẽ ra lệnh cho TRÌNH DUYỆT 
#     # tự động tải lại trang sau một khoảng thời gian.
#     # Cách này không block server Python, người dùng vẫn có thể tương tác.
#     components.html(
#         f"""
#         <meta http-equiv="refresh" content="{refresh_interval}">
#         """,
#         height=0, # Đặt chiều cao bằng 0 để nó vô hình
#     )