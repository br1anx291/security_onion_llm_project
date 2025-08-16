import json

def find_missing_alert_indices(jsonl_file_path, output_file_path, start_index=1, end_index=191):
    """
    Đọc một tệp JSONL, tìm các giá trị 'alert_index' bị thiếu trong một phạm vi nhất định
    và ghi chúng vào một tệp đầu ra.

    Args:
        jsonl_file_path (str): Đường dẫn đến tệp JSONL đầu vào.
        output_file_path (str): Đường dẫn đến tệp văn bản đầu ra.
        start_index (int): Chỉ số bắt đầu của phạm vi (mặc định là 1).
        end_index (int): Chỉ số kết thúc của phạm vi (mặc định là 191).
    """
    # Tạo một tập hợp chứa tất cả các chỉ số dự kiến
    expected_indices = set(range(start_index, end_index + 1))
    found_indices = set()

    try:
        # Mở và đọc tệp JSONL
        with open(jsonl_file_path, 'r', encoding='utf-8') as f:
            for line in f:
                try:
                    # Tải từng dòng dưới dạng một đối tượng JSON
                    data = json.loads(line)
                    # Lấy giá trị của 'alert_index' nếu có
                    if 'alert_index' in data:
                        found_indices.add(data['alert_index'])
                except json.JSONDecodeError:
                    print(f"Cảnh báo: Bỏ qua dòng không phải là JSON hợp lệ: {line.strip()}")
                except KeyError:
                    print(f"Cảnh báo: Dòng không có khóa 'alert_index': {line.strip()}")

        # Tìm các chỉ số bị thiếu bằng cách lấy phần khác biệt giữa hai tập hợp
        missing_indices = sorted(list(expected_indices - found_indices))

        # Ghi các chỉ số bị thiếu vào tệp đầu ra
        with open(output_file_path, 'w', encoding='utf-8') as f:
            if missing_indices:
                f.write("Các alert_index còn thiếu:\n")
                for index in missing_indices:
                    f.write(f"{index}\n")
                print(f"Đã tìm thấy {len(missing_indices)} chỉ số bị thiếu. Kết quả đã được ghi vào tệp '{output_file_path}'.")
            else:
                f.write("Không có alert_index nào bị thiếu trong khoảng từ {} đến {}.\n".format(start_index, end_index))
                print("Không tìm thấy chỉ số nào bị thiếu.")

    except FileNotFoundError:
        print(f"Lỗi: Không tìm thấy tệp '{jsonl_file_path}'. Vui lòng kiểm tra lại đường dẫn.")
    except Exception as e:
        print(f"Đã xảy ra lỗi không mong muốn: {e}")

# --- CÁCH SỬ DỤNG ---
if __name__ == "__main__":
    # Thay 'your_data.jsonl' bằng tên tệp JSONL của bạn
    input_filename = './ground_truth_analysis.jsonl'
    output_filename = './count.txt'
    
    find_missing_alert_indices(input_filename, output_filename)
