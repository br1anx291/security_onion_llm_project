#!/bin/bash

# Tên của phiên tmux để dễ quản lý
SESSION_NAME="my_services"

# =======================================================
# --- MENU LỰA CHỌN ---
# =======================================================

# Xóa màn hình để menu trông sạch sẽ
clear

echo "==================================================================="
echo "  Chọn chế độ chạy cho dịch vụ giám sát Alert:"
echo "-------------------------------------------------------------------"
echo "  1) Full Alerts in Day (Lấy full log đầu ngày, sau đó append)"
echo "     => Sẽ chạy script: realtime_daily_alert_sync.py"
echo ""
echo "  2) New Alerts in Day  (Chỉ lấy log mới tính từ lúc chạy)"
echo "     => Sẽ chạy script: realtime_alert_sync.py"
echo "==================================================================="

# Đọc lựa chọn của người dùng
read -p "Nhập lựa chọn của bạn (1 hoặc 2 rồi nhấn Enter): " choice

# Dùng case-statement để xác định script cần chạy dựa trên lựa chọn
case $choice in
    1)
        ALERT_SCRIPT="realtime_daily_alert_sync.py"
        echo -e "\n✅ Bạn đã chọn chế độ 'Full Alerts in Day'. Chuẩn bị chạy..."
        ;;
    2)
        ALERT_SCRIPT="realtime_alert_sync.py"
        echo -e "\n✅ Bạn đã chọn chế độ 'New Alerts in Day'. Chuẩn bị chạy..."
        ;;
    *)
        echo -e "\n❌ Lựa chọn không hợp lệ. Vui lòng chạy lại script và chọn 1 hoặc 2."
        exit 1
        ;;
esac

# Đợi 1 giây để người dùng đọc thông báo
sleep 1

# =======================================================
# --- LOGIC KHỞI ĐỘNG TMUX (Giữ nguyên từ file cũ) ---
# =======================================================

# Kiểm tra xem phiên có đang chạy không, nếu có thì thông báo và thoát
if tmux has-session -t $SESSION_NAME 2>/dev/null; then
    echo "❗️ Phiên '$SESSION_NAME' đã chạy rồi."
    echo "Để dừng, hãy dùng lệnh: ./stop_scripts.sh"
    echo "Để xem, hãy dùng lệnh: tmux attach -t $SESSION_NAME"
    exit 1
fi

echo "🚀 Bắt đầu phiên tmux '$SESSION_NAME' trong nền..."

# 1. Tạo phiên tmux mới và chạy script lấy log Zeek
tmux new-session -d -s $SESSION_NAME 'python3 logs_collector.py'

# 2. Tạo cửa sổ mới và chạy script lấy Alert đã được chọn từ menu
#    Sử dụng biến $ALERT_SCRIPT đã được gán ở trên
tmux new-window -t $SESSION_NAME "python3 $ALERT_SCRIPT"

echo "👍 Hoàn tất! Hai script đã được khởi động trong phiên tmux '$SESSION_NAME'."
echo "   - Cửa sổ 0: logs_collector.py"
echo "   - Cửa sổ 1: $ALERT_SCRIPT"
echo ""
echo "Dùng lệnh 'tmux attach -t $SESSION_NAME' để xem trực tiếp."