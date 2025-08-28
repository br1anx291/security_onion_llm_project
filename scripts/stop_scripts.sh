#!/bin/bash

# Tên của phiên tmux cần dừng (phải giống với script start)
SESSION_NAME="my_services"

echo "🛑 Đang tìm và dừng phiên tmux '$SESSION_NAME'..."

# Lệnh 'tmux kill-session' sẽ dừng phiên và tất cả tiến trình bên trong nó
tmux kill-session -t $SESSION_NAME 2>/dev/null

if [ $? -eq 0 ]; then
    echo "✅ Phiên '$SESSION_NAME' đã được dừng thành công."
else
    echo "⚠️ Không tìm thấy phiên '$SESSION_NAME' đang chạy."
fi