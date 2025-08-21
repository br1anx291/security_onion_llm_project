import pandas as pd
import numpy as np
import os

# --- CẤU HÌNH ---
# File input chứa 200 alert đã được chọn lọc và có nhãn gốc
INPUT_CSV = 'ground_truth_final2.csv'
# File output cuối cùng đã được làm giàu thông tin
OUTPUT_CSV = 'ground_truth_enriched2.csv'
# --- KẾT THÚC CẤU HÌNH ---


def main():
    """
    Hàm chính để đọc file ground truth, thêm cột phân loại FP/TP,
    và lưu ra file mới.
    """
    print(f"🚀 Bắt đầu quá trình làm giàu dữ liệu cho file '{INPUT_CSV}'...")
    
    # 1. Kiểm tra và đọc file CSV input
    if not os.path.exists(INPUT_CSV):
        print(f"❌ Lỗi: Không tìm thấy file input '{INPUT_CSV}'.")
        print("   -> Vui lòng đảm bảo bạn đã tạo file này từ các bước trước.")
        return
        
    df = pd.read_csv(INPUT_CSV)
    print(f"   -> Đã đọc thành công {len(df)} dòng.")

    # 2. NÂNG CẤP: Tạo cột 'classification_label' dựa trên 'original_label'
    # Sử dụng np.where để thực hiện việc này một cách hiệu quả:
    # cú pháp: np.where(điều_kiện, giá_trị_nếu_đúng, giá_trị_nếu_sai)
    print("   -> Đang tạo cột 'classification_label' (FP/TP)...")
    df['classification_label'] = np.where(df['original_label'] == 'BENIGN', 'FP', 'TP')

    # 3. NÂNG CẤP: Sắp xếp lại thứ tự các cột để đặt cột mới vào đúng vị trí
    # Lấy danh sách tất cả các cột hiện có
    all_columns = df.columns.tolist()
    # Xác định vị trí của cột 'original_label'
    try:
        original_label_index = all_columns.index('original_label')
    except ValueError:
        print("❌ Lỗi: Không tìm thấy cột 'original_label' trong file input.")
        return
        
    # Tạo thứ tự cột mới bằng cách chèn 'classification_label' vào sau 'original_label'
    new_column_order = (
        all_columns[:original_label_index + 1] + 
        ['classification_label'] + 
        all_columns[original_label_index + 1:-1]
    )
    df = df[new_column_order]
    
    # 4. Lưu DataFrame đã được cập nhật ra file CSV mới
    try:
        df.to_csv(OUTPUT_CSV, index=False, encoding='utf-8')
        print(f"\n🎉 Hoàn thành! Đã lưu file đã được làm giàu tại '{OUTPUT_CSV}'.")
        print("\n📊 Xem trước 5 dòng đầu của file kết quả:")
        print(df.head().to_string())
    except Exception as e:
        print(f"❌ Lỗi khi ghi file output: {e}")

if __name__ == "__main__":
    main()