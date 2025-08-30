# security_onion_llm_project/collectors/base_collector.py

from abc import ABC, abstractmethod
from typing import Any, Dict, List

class BaseCollector(ABC):
    """Defines the common interface for all data collectors."""

    def __init__(self, zeek_logs_dir: str):
        """
        Initializes the collector.

        Args:
            zeek_logs_dir (str): The path to the Zeek log directory.
        """
        self.zeek_logs_dir = zeek_logs_dir

    @property
    @abstractmethod
    def collector_name(self) -> str:
        """
        The unique name for the collector.

        This name is used as a key in the final enrichment dictionary.
        Subclasses MUST override this.
        """
        pass

    @abstractmethod
    def collect(self, log_lines: List[str]) -> Dict[str, Any] | None:
        """
        Summarizes data from a list of pre-filtered log lines.

        Subclasses MUST implement this method.

        Args:
            log_lines (List[str]): Pre-filtered, JSON-formatted log lines.

        Returns:
            Dict[str, Any] | None: A dictionary of summarized data, or None
                                  if no data is collected.
        """
        pass