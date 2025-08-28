# scripts/config.py
from config import *
from elasticsearch import Elasticsearch
from elasticsearch_dsl import Search
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
# Setup logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

# --- CẤU HÌNH ---
# Thay thế bằng thông tin của máy chủ Security Onion
remote_username = 'soc_admin'
remote_password = 'admin'
remote_host = '192.168.26.101'
ssh_tunnel_remote_port = 9200
ssh_tunnel_local_port = 9200

elastic_user = 'baonguyenqng.29@gmail.com'
elastic_pass = 'Colenbanoi'
elastic_host = 'https://localhost:9200'  # Use localhost due to SSH tunnel

# Alert query configuration
alert_severity = ['1', '2', '3']


# Đường dẫn thư mục log nguồn trên Security Onion
remote_zeek_log_path = "/nsm/zeek/logs/"
remote_zeek_spool_path = "/nsm/zeek/spool/logger/"


# Đường dẫn thư mục log đích trên máy cá nhân
# Đây là thư mục gốc, các thư mục con theo ngày sẽ được tạo bên trong.
local_zeek_log_path = "../so_logs/"
local_zeek_zip_path = "../so_logs/gz/"
local_zeek_unzip_path = "../so_logs/log/"

# Alertutput paths
alert_output_path = '../so_alerts/alerts.json'
correlated_output_path = '../so_alerts/enrich_alerts_ids2017_thur.csv'
unmatched_output_path = '../so_alerts/unmatched_alerts.csv'
unmatched_zeek_output_path ="../so_alerts/logs/unmatched_zeek.log"
zeek_log_types = ["conn", "http", "dns", "file", "ssl"]