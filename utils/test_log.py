# test_log_helper.py

import os
import datetime
import time

# Import các thành phần cần thiết từ dự án
ZEEK_LOGS_DIR = "../so_logs/log/"
from log_helper import find_log_files

def run_test():
    """Hàm chính để chạy các kịch bản kiểm thử."""
    print("--- [BẮT ĐẦU] KIỂM TRA HÀM find_log_files ---")

    # 1. Kiểm tra cấu hình đường dẫn
    base_dir = ZEEK_LOGS_DIR
    print(f"Thư mục log đang được kiểm tra (từ config.py): '{base_dir}'")
    if not os.path.isdir(base_dir):
        print(f"❌ LỖI: Thư mục '{base_dir}' không tồn tại. Vui lòng kiểm tra lại config.py.")
        return

    # 2. Chuẩn bị các trường hợp kiểm thử
    # ⚠️ THAY ĐỔI NGÀY Ở ĐÂY cho khớp với một thư mục ngày có thật trong so_logs/log/
    date_str_exists = "2025-05-25" 

    try:
        # Timestamp cho một ngày có log
        ts_exists = datetime.datetime.strptime(date_str_exists, "%Y-%m-%d").timestamp()
        # Timestamp cho ngày hôm nay (để test thư mục 'current')
        ts_current = time.time()
        # Timestamp cho một ngày chắc chắn không có log
        ts_not_exists = datetime.datetime.strptime("2020-01-01", "%Y-%m-%d").timestamp()
    except ValueError:
        print(f"❌ LỖI: Chuỗi ngày '{date_str_exists}' không hợp lệ. Vui lòng dùng định dạng YYYY-MM-DD.")
        return

    test_cases = {
        f"Log lịch sử (ngày {date_str_exists})": ts_exists,
        "Log live (hôm nay)": ts_current,
        "Log không tồn tại (ngày 2020-01-01)": ts_not_exists,
    }

    # 3. Chạy và in kết quả
    for description, timestamp in test_cases.items():
        print(f"\n--- Đang kiểm tra: {description} ---")
        
        # Gọi hàm cần test
        found_files = find_log_files(base_dir, "conn", timestamp)
        
        print(f"Hàm find_log_files đã trả về: {found_files}")
        
        if isinstance(found_files, list) and len(found_files) > 0:
            print(f"✅ KẾT QUẢ: Thành công! Tìm thấy {len(found_files)} file 'conn.*.log'.")
            for file_path, is_gzipped in found_files:
                print(f"   -> {file_path}")
        else:
            print("❌ KẾT QUẢ: Thất bại! Hàm trả về danh sách rỗng.")

    print("\n--- [KẾT THÚC] KIỂM TRA ---")


if __name__ == "__main__":
    run_test()