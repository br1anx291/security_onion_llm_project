# security_onion_llm_project/config.py

from elasticsearch import Elasticsearch
# from elasticsearch_dsl import Search
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import timedelta
import urllib3
import subprocess
import time
import json
import logging
import paramiko
import scp
import socket
import os
import gzip
import re
import hashlib
import getpass
import pandas as pd
import numpy as np

# Security Onion SSH connection
remote_username = 'soc_admin'
remote_password = 'admin'
remote_host = '192.168.26.101'
ssh_tunnel_remote_port = 9200
ssh_tunnel_local_port = 9200


# Elasticsearch credentials
elastic_user = 'baonguyenqng.29@gmail.com'
elastic_pass = 'Colenbanoi'
elastic_host = 'https://localhost:9200'  # Use localhost due to SSH tunnel

# Zeek 
ZEEK_LOGS_DIR = "./so_logs/log/"
# ZEEK_LOGS_DIR = ".\\so_logs\\log\\"
MAX_WORKERS = 10

remote_zeek_spool_path = "/nsm/zeek/spool/logger/"
local_zeek_log_path = "../so_logs"
zeek_log_types = ["conn", "http", "dns", "file", "ssl"]

# Alert query configuration
alert_severity = ['1', '2', '3']

# Alertutput paths
alert_output_path = '../so_alerts/alert_info.json'
correlated_output_path = '../so_alerts/correlated_alerts.csv'
unmatched_output_path = '../so_alerts/unmatched_alerts.csv'
unmatched_zeek_output_path ="../so_alerts/logs/unmatched_zeek.log"


# Cửa sổ thời gian (giây) để tìm kiếm conn.log khi dùng 5-tuple fallback
CONN_LOG_TIME_WINDOW_SECONDS = 660 # Giữ lại logic 60s từ code cũ, rất hợp lý

# Đường dẫn tới file quy tắc làm giàu
ENRICHMENT_RULES_PATH = "enrichment_rules.yml"

local_zeek_zip_path = "../so_logs/gz/"