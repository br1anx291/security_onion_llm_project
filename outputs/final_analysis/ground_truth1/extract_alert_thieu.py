import json
import os

def extract_and_save_individual_alerts(count_file, source_json_file, output_directory):
    """
    Đọc các chỉ số từ một tệp văn bản, trích xuất từng alert tương ứng từ
    tệp JSON nguồn và lưu mỗi alert vào một tệp JSON riêng trong một thư mục chỉ định.

    Args:
        count_file (str): Đường dẫn đến tệp .txt chứa các chỉ số bị thiếu.
        source_json_file (str): Đường dẫn đến tệp JSON nguồn chứa một danh sách các alert.
        output_directory (str): Tên của thư mục để lưu các tệp JSON đầu ra.
    """
    try:
        # ---- Bước 1: Đảm bảo thư mục đầu ra tồn tại ----
        # os.makedirs sẽ tạo thư mục và không báo lỗi nếu nó đã tồn tại.
        os.makedirs(output_directory, exist_ok=True)
        print(f"Thư mục đầu ra '{output_directory}' đã sẵn sàng.")

        # ---- Bước 2: Đọc các con số từ count.txt ----
        print(f"Đang đọc các chỉ số từ '{count_file}'...")
        # Sử dụng dictionary để lưu cả alert_index gốc và index của list
        target_indices = {}
        with open(count_file, 'r', encoding='utf-8') as f:
            # Bỏ qua dòng tiêu đề nếu có
            next(f, None)  
            for line in f:
                line = line.strip()
                if line.isdigit():
                    original_number = int(line)
                    # Chuyển đổi alert_index (bắt đầu từ 1) thành chỉ số list (bắt đầu từ 0)
                    list_index = original_number - 1
                    target_indices[list_index] = original_number
        
        if not target_indices:
            print("Tệp 'count.txt' trống hoặc không chứa số hợp lệ. Dừng xử lý.")
            return

        print(f"Đã đọc {len(target_indices)} chỉ số cần lấy.")

        # ---- Bước 3: Đọc file JSON nguồn ----
        print(f"Đang tải dữ liệu từ '{source_json_file}'...")
        with open(source_json_file, 'r', encoding='utf-8') as f:
            all_alerts = json.load(f)

        if not isinstance(all_alerts, list):
            print(f"Lỗi: Nội dung trong '{source_json_file}' không phải là một danh sách JSON.")
            return

        # ---- Bước 4: Trích xuất và ghi từng alert ra file riêng ----
        print("Bắt đầu trích xuất và ghi các alert...")
        alerts_written = 0
        for list_index, original_number in target_indices.items():
            if 0 <= list_index < len(all_alerts):
                # Lấy alert tương ứng
                alert_to_save = all_alerts[list_index]
                
                # Tạo tên và đường dẫn file
                output_filename = f"{original_number}_json_thieu.json"
                output_filepath = os.path.join(output_directory, output_filename)
                
                # Ghi alert vào file JSON
                with open(output_filepath, 'w', encoding='utf-8') as f:
                    json.dump(alert_to_save, f, ensure_ascii=False, indent=4)
                
                print(f"  -> Đã lưu alert '{original_number}' vào file '{output_filepath}'")
                alerts_written += 1
            else:
                print(f"Cảnh báo: Chỉ số {original_number} (index trong list: {list_index}) nằm ngoài phạm vi. Bỏ qua.")
        
        print(f"\nHoàn tất! ✨ Đã ghi thành công {alerts_written} tệp.")

    except FileNotFoundError as e:
        print(f"Lỗi: Không tìm thấy tệp '{e.filename}'. Vui lòng kiểm tra lại đường dẫn.")
    except json.JSONDecodeError:
        print(f"Lỗi: Tệp '{source_json_file}' không chứa JSON hợp lệ.")
    except Exception as e:
        print(f"Đã xảy ra lỗi không mong muốn: {e}")

# --- CÁCH SỬ DỤNG ---
if __name__ == "__main__":
    count_filename = 'count.txt'
    # Thay 'source_alerts.json' bằng tên tệp JSON nguồn của bạn
    source_json_filename = '../../../so_alerts/ground_truth.json' 
    output_folder = './ground_truth_thieu'

    extract_and_save_individual_alerts(count_filename, source_json_filename, output_folder)

# # --- CÁCH SỬ DỤNG ---
# if __name__ == "__main__":
#     # Tên các tệp đầu vào và đầu ra
#     count_filename = 'count.txt'
#     # Thay 'source_alerts.json' bằng tên tệp JSON nguồn của bạn
#     source_json_filename = '../../../so_alerts/ground_truth.json' 
#     output_filename = './gt_thieu.json'

#     extract_alerts_by_index(count_filename, source_json_filename, output_filename)