import pandas as pd
import numpy as np

# --- CẤU HÌNH BƯỚC 2 ---
MAPPED_ALERTS_FILE = 'mapped_alerts.csv'
FINAL_OUTPUT_FILE = 'ground_truth_final2.csv'

NUM_FP_SAMPLES = 50
NUM_TP_SAMPLES = 150
RANDOM_STATE = 42

# Hạn ngạch "lý tưởng" cho từng nhóm
TP_STRATEGY = {
    'Web Attacks': {
        'labels': ['Web Attack - XSS', 'Web Attack - Sql Injection', 'Web Attack - Brute Force'],
        'samples': 45
    },
    'Infiltration & Botnet': {
        'labels': ['Infiltration', 'Bot'],
        'samples': 30
    },
    'Brute Force': {
        'labels': ['FTP-Patator', 'SSH-Patator'],
        'samples': 20
    },
    'DoS_Scan': {
        'labels': ['DDoS', 'PortScan'],
        'samples': 55 
    },
}
# --- KẾT THÚC CẤU HÌNH ---

def main_step2():
    print("\n🚀 BƯỚC 2: Bắt đầu lấy mẫu phân tầng có 'Hạn ngạch' ĐỘNG...")
    
    try:
        df = pd.read_csv(MAPPED_ALERTS_FILE)
        df['original_label'] = df['original_label'].str.strip()
    except FileNotFoundError:
        print(f"❌ Lỗi: Không tìm thấy file '{MAPPED_ALERTS_FILE}'. Vui lòng chạy script Bước 1 trước.")
        return

    fp_alerts = df[df['original_label'] == 'BENIGN'].copy()
    tp_alerts = df[df['original_label'] != 'BENIGN'].copy()

    print(f"📊 Thống kê 'Siêu Bảng':")
    print(f"   -> Tìm thấy {len(fp_alerts)} alert FP và {len(tp_alerts)} alert TP.")

    # Lấy mẫu FP
    fp_sample = fp_alerts.sample(n=min(NUM_FP_SAMPLES, len(fp_alerts)), random_state=RANDOM_STATE)
    print(f"   -> ✅ Đã lấy {len(fp_sample)} mẫu FP.")

    # NÂNG CẤP: Logic lấy mẫu TP động 2 bước
    if len(tp_alerts) < NUM_TP_SAMPLES:
        print(f"   -> ⚠️ Cảnh báo: Tổng số alert TP ({len(tp_alerts)}) ít hơn 150. Sẽ lấy tất cả.")
        tp_sample_final = tp_alerts
    else:
        print("\n🎯 Bắt đầu lấy mẫu TP theo chiến lược động...")
        list_of_tp_samples = []
        
        # Tạo một bản sao của tp_alerts để theo dõi các alert chưa được chọn
        remaining_tp_alerts = tp_alerts.copy()

        # Bước 1: Lấy mẫu tối thiểu theo hạn ngạch
        print("   -> Bước 1: Lấy mẫu theo hạn ngạch lý tưởng...")
        for category, details in TP_STRATEGY.items():
            labels_in_category = details['labels']
            num_to_sample_ideal = details['samples']
            
            category_df = remaining_tp_alerts[remaining_tp_alerts['original_label'].isin(labels_in_category)]
            
            num_to_sample_actual = min(num_to_sample_ideal, len(category_df))
            
            if num_to_sample_actual > 0:
                actual_samples = category_df.sample(n=num_to_sample_actual, random_state=RANDOM_STATE)
                list_of_tp_samples.append(actual_samples)
                # Loại bỏ những mẫu đã chọn ra khỏi bể chứa
                remaining_tp_alerts.drop(actual_samples.index, inplace=True)
                print(f"      -> Nhóm '{category}': Lấy {len(actual_samples)}/{num_to_sample_ideal} mẫu.")

        # Gộp các mẫu đã lấy ở bước 1
        current_tp_samples_df = pd.concat(list_of_tp_samples)
        
        # Bước 2: Bù đắp phần thiếu hụt
        shortfall = NUM_TP_SAMPLES - len(current_tp_samples_df)
        print(f"\n   -> Bước 2: Bù đắp phần thiếu hụt...")
        print(f"      -> Số mẫu đã có: {len(current_tp_samples_df)}. Cần bù: {shortfall} mẫu.")

        if shortfall > 0 and not remaining_tp_alerts.empty:
            num_to_compensate = min(shortfall, len(remaining_tp_alerts))
            
            compensation_samples = remaining_tp_alerts.sample(n=num_to_compensate, random_state=RANDOM_STATE)
            list_of_tp_samples.append(compensation_samples)
            print(f"      -> ✅ Đã lấy thêm {len(compensation_samples)} mẫu ngẫu nhiên từ phần còn lại.")
        
        tp_sample_final = pd.concat(list_of_tp_samples)

    # Gộp và lưu file cuối cùng
    final_df = pd.concat([fp_sample, tp_sample_final], ignore_index=True)
    final_df = final_df.sample(frac=1, random_state=RANDOM_STATE).reset_index(drop=True)

    final_df.to_csv(FINAL_OUTPUT_FILE, index=False, encoding='utf-8')

    print(f"\n🎉 Hoàn thành! Đã tạo file ground truth cuối cùng tại '{FINAL_OUTPUT_FILE}'.")
    print(f"   -> Tổng số alert: {len(final_df)} ({len(fp_sample)} FP và {len(tp_sample_final)} TP)")
    print("\n📊 Bảng tổng kết nhãn gốc trong file cuối cùng:")
    print(final_df['original_label'].value_counts())


if __name__ == "__main__":
    main_step2()