# security_onion_llm_project/collectors/base_collector.py

from abc import ABC, abstractmethod

class BaseCollector(ABC):
    """
    Lớp cơ sở trừu tượng (Abstract Base Class) cho tất cả các collector.
    
    Nó định nghĩa một giao diện (interface) chung mà mọi collector phải thực thi.
    Điều này đảm bảo rằng EnrichmentManager có thể làm việc với bất kỳ collector nào
    một cách nhất quán mà không cần biết logic bên trong của nó.
    """
    
    def __init__(self, zeek_logs_dir: str):
        """
        Hàm khởi tạo nhận vào đường dẫn thư mục log Zeek.
        
        Args:
            zeek_logs_dir (str): Đường dẫn từ config.py.
        """
        self.zeek_logs_dir = zeek_logs_dir

    @property
    @abstractmethod
    def collector_name(self) -> str:
        """
        Một thuộc tính (property) trừu tượng.
        Mỗi lớp con BẮT BUỘC phải định nghĩa thuộc tính này.
        Nó trả về tên của collector dưới dạng chuỗi (ví dụ: 'dns', 'ssl').
        Tên này sẽ được dùng làm key trong dictionary kết quả làm giàu cuối cùng.
        """
        pass

    @abstractmethod
    def collect(self, uid: str, alert_timestamp: float) -> dict | None:
        """
        Phương thức trừu tượng (abstract method) để thu thập và tóm tắt dữ liệu.
        Mỗi lớp con BẮT BUỘC phải triển khai (implement) phương thức này.
        
        Args:
            uid (str): UID của kết nối Zeek cần điều tra.
            alert_timestamp (float): Thời điểm của cảnh báo, dùng để tìm file log.

        Returns:
            dict | None: 
                - Một dictionary chứa dữ liệu đã được tóm tắt nếu tìm thấy.
                - None nếu không tìm thấy thông tin liên quan.
        """
        pass