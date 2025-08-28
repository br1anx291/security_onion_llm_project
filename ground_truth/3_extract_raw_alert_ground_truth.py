import pandas as pd
import json
from tqdm import tqdm

# --- CẤU HÌNH ---
# File input chứa 200 alert đã được chọn lọc
FINAL_GROUND_TRUTH_CSV = 'ground_truth_final2.csv'
# File input chứa 10,000 alert thô ("đại dương")
ALL_ALERTS_JSON = 'all_alerts.json'
# File output cuối cùng
RAW_ALERTS_OUTPUT_JSON = 'ground_truth2.json'
# --- KẾT THÚC CẤU HÌNH ---


def build_raw_alert_map(alerts_file_path):
    """
    Xây dựng một dictionary để tra cứu alert thô một cách nhanh chóng.
    Key là một tuple định danh duy nhất, value là toàn bộ object alert thô.
    """
    print(f" ottimizzazione: Pre-elaborazione del file '{alerts_file_path}' per creare una mappa di ricerca...")
    raw_alert_map = {}
    
    try:
        with open(alerts_file_path, 'r', encoding='utf-8') as f:
            all_alerts = json.load(f)
    except Exception as e:
        print(f"❌ Errore: Impossibile leggere il file JSON degli avvisi. Motivo: {e}")
        return None

    for alert in tqdm(all_alerts, desc="   -> Indicizzazione degli avvisi non elaborati"):
        # Tạo một key định danh duy nhất cho mỗi alert.
        # Kết hợp timestamp, tên rule và IP nguồn là một lựa chọn tốt để đảm bảo tính duy nhất.
        timestamp = alert.get('@timestamp')
        rule_name = alert.get('rule', {}).get('name')
        src_ip = alert.get('source', {}).get('ip')

        if all([timestamp, rule_name, src_ip]):
            key = (timestamp, rule_name, src_ip)
            # Giả định key là duy nhất, nếu không, có thể lưu vào một danh sách
            raw_alert_map[key] = alert 
            
    print(f"   -> Hoàn thành. Đã xây dựng bản đồ với {len(raw_alert_map)} avvisi unici.")
    return raw_alert_map


def main():
    """
    Hàm chính để tìm và trích xuất các alert thô.
    """
    print("🚀 Bắt đầu quá trình trích xuất alert thô...")
    
    # 1. Xây dựng bản đồ tra cứu từ file alert thô
    raw_alert_map = build_raw_alert_map(ALL_ALERTS_JSON)
    if raw_alert_map is None:
        return

    # 2. Đọc file ground truth đã chọn lọc
    try:
        selected_alerts_df = pd.read_csv(FINAL_GROUND_TRUTH_CSV)
    except FileNotFoundError:
        print(f"❌ Errore: File ground truth '{FINAL_GROUND_TRUTH_CSV}' non trovato.")
        return
        
    print(f"🔎 Đã đọc {len(selected_alerts_df)} alert đã chọn. Bắt đầu tìm kiếm alert thô tương ứng...")

    found_raw_alerts = []
    alerts_not_found_count = 0
    
    # 3. Lặp qua từng alert đã chọn và tìm alert thô
    for _, row in tqdm(selected_alerts_df.iterrows(), total=len(selected_alerts_df), desc="   -> Estrazione degli avvisi non elaborati"):
        # Tạo lại key định danh từ thông tin trong file CSV
        lookup_key = (row['timestamp'], row['alert_name'], row['source_ip'])
        
        # Tra cứu alert thô trong bản đồ
        raw_alert = raw_alert_map.get(lookup_key)
        
        if raw_alert:
            found_raw_alerts.append(raw_alert)
        else:
            alerts_not_found_count += 1
            # In ra cảnh báo nếu không tìm thấy để tiện gỡ lỗi
            # print(f"\n   -> ⚠️ Cảnh báo: Không tìm thấy alert thô cho key: {lookup_key}")

    # 4. Báo cáo kết quả và ghi file
    print(f"\n🎉 Hoàn thành!")
    print(f"   -> ✅ Tìm thấy {len(found_raw_alerts)} alert thô tương ứng.")
    if alerts_not_found_count > 0:
        print(f"   -> ⚠️ Không tìm thấy {alerts_not_found_count} alert thô.")
        
    if not found_raw_alerts:
        print("   -> Không có dữ liệu để ghi ra file.")
        return

    print(f"   -> Đang ghi kết quả vào file '{RAW_ALERTS_OUTPUT_JSON}'...")
    try:
        with open(RAW_ALERTS_OUTPUT_JSON, 'w', encoding='utf-8') as f:
            # Ghi file JSON với định dạng đẹp để dễ đọc
            json.dump(found_raw_alerts, f, indent=4, ensure_ascii=False)
        print("   -> Ghi file thành công!")
    except Exception as e:
        print(f"❌ Lỗi khi ghi file JSON: {e}")

if __name__ == "__main__":
    main()