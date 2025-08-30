
# --- CONFIGURATION ---
# Replace with your Security Onion server details
REMOTE_USERNAME = 'soc_admin'
REMOTE_HOST = '192.168.26.101'
SSH_TUNNEL_REMOTE_PORT = 9200
SSH_TUNNEL_LOCAL_PORT = 9200

ELASTIC_USER = 'baonguyenqng.29@gmail.com'
ELASTIC_PASS = 'Colenbanoi'
ELASTIC_HOST = 'https://localhost:9200'  # Use localhost due to SSH tunnel

# Alert query configuration
ALERT_SEVERITY = ['1', '2', '3']

# Source log directory paths on Security Onion
REMOTE_ZEEK_LOG_PATH = "/nsm/zeek/logs/"
REMOTE_ZEEK_SPOOL_PATH = "/nsm/zeek/spool/logger/"


# Destination log directory paths on the local machine
# This is the root directory; daily subdirectories will be created inside.
LOCAL_ZEEK_LOG_PATH = "../so_logs/"
LOCAL_ZEEK_ZIP_PATH = "../so_logs/gz/"
LOCAL_ZEEK_UNZIP_PATH = "../so_logs/log/"

# Alert output paths
ALERT_OUTPUT_PATH = '../so_alerts/alerts.json'

REMOTE_KEY_PATH = "/root/.ssh/id_ed25519.pub"