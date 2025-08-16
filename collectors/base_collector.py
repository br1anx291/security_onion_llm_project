# security_onion_llm_project/collectors/base_collector.py

from abc import ABC, abstractmethod
from typing import List, Dict, Any

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
    def collect(self, log_lines: List[str]) -> Dict[str, Any] | None:
        """
        Phương thức trừu tượng để thu thập và tóm tắt dữ liệu từ các dòng log.
        Mỗi lớp con BẮT BUỘC phải triển khai (implement) phương thức này.
        
        Args:
            log_lines (List[str]): Một danh sách các dòng log (dưới dạng chuỗi JSON)
                                   đã được EnrichmentManager lọc sẵn cho collector này.

        Returns:
            Dict[str, Any] | None: 
                - Một dictionary chứa dữ liệu đã được tóm tắt nếu tìm thấy.
                - None nếu không có thông tin liên quan hoặc không có gì để báo cáo.
        """
        pass