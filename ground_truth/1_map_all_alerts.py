import pandas as pd
import json
import glob
import os
from tqdm import tqdm
import logging

# --- CẤU HÌNH BƯỚC 1 ---
CSV_FILES_PATTERN = '*_ISCX.csv'
ALERTS_FILE = 'alerts_CICIDS2017.json'
OUTPUT_MAPPED_FILE = 'mapped_alerts.csv'

PROTOCOL_MAP = {'TCP': 6, 'UDP': 17, 'ICMP': 1}
# --- KẾT THÚC CẤU HÌNH ---

def create_connection_lookup_table(csv_pattern):
    """
    Đọc tất cả các file CSV, gom nhóm theo 5-tuple và tổng hợp TẤT CẢ các nhãn duy nhất.
    """
    logging.info(f"Đang đọc và gộp các file CSV từ mẫu: '{csv_pattern}'...")
    csv_files = glob.glob(csv_pattern)
    if not csv_files:
        logging.error("Không tìm thấy file CSV nào. Dừng chương trình.")
        return None

    required_cols = ['Source IP', 'Source Port', 'Destination IP', 'Destination Port', 'Protocol', 'Label']
    list_of_dfs = []
    for f in tqdm(csv_files, desc="   -> Đang tải file CSV"):
        try:
            df = pd.read_csv(f, usecols=lambda c: c.strip() in required_cols, encoding='latin-1', low_memory=False)
            df.columns = df.columns.str.strip()
            list_of_dfs.append(df)
        except Exception as e:
            logging.warning(f"Lỗi khi đọc file {f}: {e}")

    if not list_of_dfs:
        logging.error("Không đọc được file CSV nào. Dừng chương trình.")
        return None

    logging.info("Đang gộp và xử lý 'Bảng tra cứu'...")
    connections_df = pd.concat(list_of_dfs, ignore_index=True)
    
    connections_df.rename(columns={
        'Source IP': 'source_ip', 'Source Port': 'source_port',
        'Destination IP': 'destination_ip', 'Destination Port': 'destination_port',
        'Protocol': 'protocol', 'Label': 'original_label'
    }, inplace=True)

    # NÂNG CẤP: Gom nhóm theo 5-tuple và tổng hợp các nhãn duy nhất
    logging.info("Gom nhóm theo 5-tuple và tổng hợp các nhãn duy nhất...")
    # Bỏ qua các dòng có giá trị null trong các cột chính
    connections_df.dropna(subset=['source_ip', 'source_port', 'destination_ip', 'destination_port', 'protocol'], inplace=True)
    
    # Ép kiểu dữ liệu để groupby hoạt động ổn định
    for col in ['source_port', 'destination_port', 'protocol']:
        connections_df[col] = connections_df[col].astype(int)
        
    lookup_table = connections_df.groupby(
        ['source_ip', 'source_port', 'destination_ip', 'destination_port', 'protocol']
    )['original_label'].unique().apply(list)
    
    logging.info(f"Đã tạo xong 'Bảng tra cứu' với {len(lookup_table)} connections duy nhất.")
    return lookup_table

def main_step1():
    print("🚀 BƯỚC 1: Bắt đầu tạo 'Siêu Bảng' (mapped_alerts.csv)...")
    
    connections_lookup = create_connection_lookup_table(CSV_FILES_PATTERN)
    if connections_lookup is None:
        return

    try:
        with open(ALERTS_FILE, 'r', encoding='utf-8') as f:
            all_alerts = json.load(f)
    except Exception as e:
        print(f"❌ Lỗi: Không thể đọc file alert '{ALERTS_FILE}'. Lý do: {e}")
        return

    print(f"🔎 Đang lặp qua {len(all_alerts)} alert để tìm nhãn gốc...")
    mapped_alerts_data = []
    for alert in tqdm(all_alerts, desc="   -> Đang ánh xạ alert"):
        src_ip = alert.get('source', {}).get('ip')
        src_port = alert.get('source', {}).get('port')
        dest_ip = alert.get('destination', {}).get('ip')
        dest_port = alert.get('destination', {}).get('port')
        transport_str = alert.get('network', {}).get('transport')
        protocol = PROTOCOL_MAP.get(str(transport_str).upper(), -1)

        if not all([src_ip, src_port, dest_ip, dest_port, protocol != -1]):
            continue

        try:
            # Tra cứu trong bảng, kết quả trả về là một list, ví dụ: ['BENIGN'] hoặc ['BENIGN', 'DDoS']
            match_labels = connections_lookup.loc[(src_ip, src_port, dest_ip, dest_port, protocol)]
            
            # NÂNG CẤP: Chuyển list các label thành một chuỗi duy nhất, sắp xếp để nhất quán
            original_label_str = ', '.join(map(str, sorted(match_labels)))
            
            mapped_alerts_data.append({
                'timestamp': alert.get('@timestamp'),
                'alert_name': alert.get('rule', {}).get('name'),
                'category': alert.get('rule', {}).get('category'),
                'severity': alert.get('rule', {}).get('severity'),
                'source_ip': src_ip,
                'source_port': src_port,
                'destination_ip': dest_ip,
                'destination_port': dest_port,
                'transport': transport_str,
                'original_label': original_label_str # Ghi chuỗi đã được xử lý
            })
        except KeyError:
            continue

    if not mapped_alerts_data:
        print("⚠️ Không có alert nào được ánh xạ. Vui lòng kiểm tra lại dữ liệu.")
        return

    print(f"\n🎉 Hoàn thành Bước 1! Đã ánh xạ thành công {len(mapped_alerts_data)} alert.")
    print(f"   -> Đang lưu vào file '{OUTPUT_MAPPED_FILE}'...")
    
    df_mapped = pd.DataFrame(mapped_alerts_data)
    df_mapped.to_csv(OUTPUT_MAPPED_FILE, index=False, encoding='utf-8')
    print("   -> Đã lưu file thành công!")

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')
    main_step1()