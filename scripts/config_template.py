# ==============================================================================
# CONFIGURATION TEMPLATE
#
# Instructions:
# 1. Copy this file and rename it to 'config.py'.
# 2. Fill in the placeholder values (e.g., 'your_so_host_ip', 'your_password')
#    with your actual server details and credentials.
# 3. IMPORTANT: Make sure 'config.py' is listed in your .gitignore file
#    and is NEVER committed to the repository.
# ==============================================================================

# --- Security Onion Server Details ---
# Replace with your Security Onion server details
REMOTE_USERNAME = 'soc_admin'
REMOTE_HOST = 'your_so_host_ip'  # e.g., '192.168.26.101'
REMOTE_KEY_PATH = '/path/to/your/ssh/private_key' # e.g., 'C:/Users/User/.ssh/id_rsa'

# --- SSH Tunnel Configuration ---
# These are common defaults and may not need to be changed.
SSH_TUNNEL_REMOTE_PORT = 9200
SSH_TUNNEL_LOCAL_PORT = 9200

# --- Elasticsearch Credentials ---
ELASTIC_USER = 'your_elastic_user'
ELASTIC_PASS = 'your_elastic_password'
# This should typically remain localhost because of the SSH tunnel.
ELASTIC_HOST = 'https://localhost:9200'

# --- Alert Query Configuration ---
# Severity levels to query from Elasticsearch.
ALERT_SEVERITY = ['1', '2', '3']

# --- Log Directory Paths on Security Onion ---
# These are standard paths and may not need to be changed.
REMOTE_ZEEK_LOG_PATH = "/nsm/zeek/logs/"
REMOTE_ZEEK_SPOOL_PATH = "/nsm/zeek/spool/logger/"

# --- Local Directory Paths ---
# These paths are relative to the script's location.
LOCAL_ZEEK_LOG_PATH = "../so_logs/"
LOCAL_ZEEK_ZIP_PATH = "../so_logs/gz/"
LOCAL_ZEEK_UNZIP_PATH = "../so_logs/log/"

# --- Output File Paths ---
ALERT_OUTPUT_PATH = '../so_alerts/alerts.json'