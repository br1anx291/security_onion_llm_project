
from config import *

zeek_log_fields = {
    "conn": [
        "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
        "proto", "service", "community_id", "conn_state", "history",
        "duration", "orig_bytes", "resp_bytes", "local_orig", "missed_bytes"
    ],
    "http": [
        "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto",
        "method", "host", "uri", "referrer", "user_agent",
        "request_body_len", "response_body_len",
        "status_code", "status_msg", "info_code", "info_msg", "tags",
        "orig_fuids", "orig_filenames", "orig_mime_types",
        "resp_fuids", "resp_filenames", "resp_mime_types"
    ],
    "dns": [
        "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
        "proto", "query", "qclass", "qclass_name", "qtype", "qtype_name",
        "rcode", "rcode_name", "answers", "TTLs", "rejected"
    ],
    "file": [
        "ts", "fuid", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
        "source", "depth", "analyzers", "mime_type", "duration", "local_orig", "is_orig",
        "seen_bytes","total_bytes","missing_bytes", "overflow_bytes","timedout","md5",
        "sha1","extracted","extracted_cutoff","extracted_size"
    ],
    "ssl": [
        "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
        "version", "cipher", "resumed", "established",
        "ssl_history", "cert_chain_fps", "client_cert_chain_fps",
        "validation_status", "ja3", "ja3s",
        "curve", "server_name", "sni_matches_cert", "next_protocol"
    ]
}

log_ts_column = {
    "conn": "zeek_ts", "http": "http_ts", "dns": "dns_ts",
    "file": "file_ts", "ssl": "ssl_ts"
}

log_summary_fields = {
    "http": "uri",
    "dns": "query",
    "file": "fuid",
    "ssl": "ja3"
}

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")


# -----------------SNAPSHOT--------------#
def get_conn_snapshot(base_dir):
    snapshot = {}
    for folder in os.listdir(base_dir):
        if not folder.startswith('20'):
            continue
        csv_dir = os.path.join(base_dir, folder, 'csv')
        if not os.path.isdir(csv_dir):
            continue
        for file in os.listdir(csv_dir):
            if file.startswith('conn') and file.endswith('.csv'):
                full_path = os.path.join(csv_dir, file)
                snapshot[os.path.join(folder, file)] = os.path.getmtime(full_path)
    return snapshot

def get_alert_snapshot(alert_path):
    if os.path.exists(alert_path):
        return os.path.getmtime(alert_path)
    else:
        logging.error(f"❌ Alert file not found: {alert_path}")
        return None

def load_snapshot(snapshot_path):
    if os.path.exists(snapshot_path):
        with open(snapshot_path, 'r') as f:
            return json.load(f)
    return {}

def save_snapshot(snapshot, snapshot_path):
    with open(snapshot_path, 'w') as f:
        json.dump(snapshot, f, indent=2)

# ---------------- UTILS ---------------- #
def hash_5tuple(ip1, port1, ip2, port2, proto):
    key = f"{ip1}:{port1}-{ip2}:{port2}-{proto}"
    return hashlib.sha256(key.encode()).hexdigest()

def load_alerts(path):
    if not os.path.exists(path):
        logging.error(f"Alert file not found: {path}")
        return None
    df = pd.read_csv(path)
    if 'community_id' not in df.columns and 'network.community_id' in df.columns:
        df.rename(columns={'network.community_id': 'community_id'}, inplace=True)
    df['timestamp'] = pd.to_datetime(df.get('@timestamp', df.get('timestamp')), errors='coerce')
    return df

def load_zeek_logs(log_type, base_dir, fields_dict):
    all_dfs = []
    
    for folder in os.listdir(base_dir):
        if not re.match(r'\d{4}-\d{2}-\d{2}', folder):
            continue
        csv_dir = os.path.join(base_dir, folder, "csv")
        if not os.path.isdir(csv_dir):
            continue
        for file in os.listdir(csv_dir):
            if file.startswith(log_type) and file.endswith(".csv"):
                full_path = os.path.join(csv_dir, file)
                try:
                    df = pd.read_csv(full_path, usecols=lambda c: c in fields_dict[log_type])
                    all_dfs.append(df)
                    logging.info(f"Loaded {log_type.upper()} log {file} from {folder}")
                except Exception as e:
                    logging.warning(f"❌ Failed to read {log_type} log {full_path}: {e}")
    if not all_dfs:
        return pd.DataFrame()
    df = pd.concat(all_dfs, ignore_index=True)
    df[log_ts_column[log_type]] = pd.to_datetime(df['ts'], unit='s', errors='coerce')
    
    # Deduplication based on conn_state priority
    if 'community_id' in df.columns:
        preferred_state = ['SF', 'S0']
        df['state_rank'] = df['conn_state'].apply(lambda x: preferred_state.index(x) if x in preferred_state else len(preferred_state))
        df = df.sort_values(['community_id', 'state_rank', 'zeek_ts'])
        df = df.drop_duplicates(subset='community_id', keep='first')
        df.drop(columns=['state_rank'], inplace=True)
        logging.info(f"Deduplicated Zeek conn logs to {len(df)} rows by community_id")
    else:
        logging.warning(f"No community_id found in Zeek {log_type} logs to deduplicate")

    return df


def enrich_alerts_with_zeek(alert_df, zeek_conn_df):

    # Build 5-tuple hash for fallback
    alert_df['5tuple_hash'] = alert_df.apply(lambda row: hash_5tuple(
        row.get('source.ip') or row.get('id.orig_h'),
        row.get('source.port') or row.get('id.orig_p'),
        row.get('destination.ip') or row.get('id.resp_h'),
        row.get('destination.port') or row.get('id.resp_p'),
        row.get('network.transport') or row.get('proto')
    ), axis=1)
    zeek_conn_df['5tuple_hash'] = zeek_conn_df.apply(lambda row: hash_5tuple(
        row.get('id.orig_h'), row.get('id.orig_p'),
        row.get('id.resp_h'), row.get('id.resp_p'),
        row.get('proto')
    ), axis=1)

    # Phase 1: Merge by community_id
    merged_df = pd.merge(alert_df, zeek_conn_df, on='community_id', how='left', suffixes=('', '_zeek'))
    matched_df = merged_df[~merged_df['uid'].isna()].copy()
    unmatched_alerts = merged_df[merged_df['uid'].isna()].copy()
    logging.info(f"[Phase 1] Alerts matched via community_id: {len(matched_df)}")
    logging.info(f"[Phase 1] Alerts to fallback using 5-tuple: {len(unmatched_alerts)}")
    
    
    # Phase 2: Fallback match using hash + time window  
    fallback_rows = []
    for _, alert in unmatched_alerts.iterrows():
        candidates = zeek_conn_df[zeek_conn_df['5tuple_hash'] == alert['5tuple_hash']].copy()
        if pd.isna(alert['timestamp']) or candidates.empty:
            continue
        candidates['time_diff'] = abs(candidates['zeek_ts'] - alert['timestamp'])
        best_match = candidates[candidates['time_diff'] <= timedelta(seconds=60)].sort_values('time_diff').head(1)
        if not best_match.empty:
            alert_row_df = alert.to_frame().T.reset_index(drop=True)
            zeek_row_df = best_match.reset_index(drop=True)
            zeek_row_df.columns = [f"{col}_zeek" for col in zeek_row_df.columns]
            combined = pd.concat([alert_row_df, zeek_row_df], axis=1)
            fallback_rows.append(combined)

    fallback_df = pd.concat(fallback_rows, ignore_index=True) if fallback_rows else pd.DataFrame()
    logging.info(f"[Phase 2] Alerts matched via 5-tuple fallback: {len(fallback_df)}")
        
    final_df = pd.concat([matched_df, fallback_df], ignore_index=True)
    unmatched_count = len(alert_df) - len(final_df)
    logging.info(f"[Final] Total unmatched alerts: {unmatched_count}")
    
    # Export unmatched for analysis    
    if 'log.id.uid' in final_df.columns:
        matched_ids = final_df['log.id.uid'].dropna().unique().tolist()
        unmatched_df = alert_df[~alert_df['log.id.uid'].isin(matched_ids)]
        unmatched_df.to_csv(unmatched_output_path, index=False)
        logging.info(f"⚠️ Unmatched alerts saved to {unmatched_output_path}")
    return final_df

def enrich_with_uid(base_df, enrich_df, name=""):
    if enrich_df.empty or 'uid' not in base_df.columns:
        logging.warning(f"⚠️ Cannot enrich with {name}: missing uid or empty log")
        return base_df

    # PREPROCESS: Reduce enrich_df to one row per uid
    enrich_reduced = enrich_df.groupby('uid').first().reset_index()
    logging.info(f"🔧 Reduced {name} logs to {len(enrich_reduced)} unique uid rows.")

    merged = pd.merge(base_df, enrich_reduced, how='left', on='uid', suffixes=('', f'_{name}'))
    
    summary_field = log_summary_fields.get(name)
    if summary_field and summary_field in merged.columns:
        enriched_rows = merged[summary_field].notna().sum()
        logging.info(f"✅ {name} enrichment complete. Rows with {name} data: {enriched_rows}")
    else:
        logging.info(f"✅ {name} enrichment complete. No summary field found.")

    return merged

def deduplicate_ip_port_fields(df):
    log_types = ['http', 'dns', 'file', 'ssl']
    base_fields = ['id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p']

    for log_type in log_types:
        suffix = f"_{log_type}"
        conflict = False
        for field in base_fields:
            log_field = field + suffix
            if log_field in df.columns:
                # So sánh bằng cách bỏ NaN và so khớp giá trị thực sự
                base_series = df[field]
                compare_series = df[log_field]

                mask = base_series.notna() & compare_series.notna()
                if mask.sum() == 0:
                    # Không có giá trị nào để so, skip
                    continue

                identical = (base_series[mask] == compare_series[mask]).all()
                if identical:
                    df.drop(columns=[log_field], inplace=True)
                    logging.info(f"🧹 Dropped duplicated field {log_field}")
                else:
                    new_name = f"{field}_{log_type}_alt"
                    df.rename(columns={log_field: new_name}, inplace=True)
                    logging.info(f"⚠️ Field {log_field} differs from base, renamed to {new_name}")
                    conflict = True

        if conflict:
            logging.warning(f"⚠️ Detected IP/Port mismatch in {log_type.upper()} logs.")
    return df

def deduplicate_ts_by_threshold_rowwise(df, threshold_sec=1):
    base_field = 'ts'
    log_types = ['http', 'dns', 'file', 'ssl']

    for log_type in log_types:
        ts_field = f"{base_field}_{log_type}"
        if ts_field not in df.columns:
            continue

        base_series = df[base_field]
        compare_series = df[ts_field]

        # So sánh: bỏ NaN, chỉ lấy dòng có cả 2 giá trị
        mask = base_series.notna() & compare_series.notna()
        if mask.sum() == 0:
            continue  # skip nếu không có cặp nào

        # Tính chênh lệch tuyệt đối (giây float)
        diff_series = abs(base_series[mask] - compare_series[mask])

        # Với dòng nào nhỏ hơn threshold, set NaN
        drop_mask = diff_series < threshold_sec
        dropped_count = drop_mask.sum()

        df.loc[mask[mask].index[drop_mask], ts_field] = np.nan

        if dropped_count > 0:
            logging.info(f"🧹 Cleared {dropped_count} rows in {ts_field} (diff < {threshold_sec}s)")

        # Nếu còn dòng có diff ≥ threshold → rename cột để giữ lại
        keep_count = (~drop_mask).sum()
        if keep_count > 0:
            new_name = f"{ts_field}_alt"
            df.rename(columns={ts_field: new_name}, inplace=True)
            logging.info(f"⚠️ Field {ts_field} has {keep_count} rows with diffs ≥ {threshold_sec}s, renamed to {new_name}")
        else:
            # Nếu tất cả dòng bị NaN → drop luôn cột
            df.drop(columns=[ts_field], inplace=True)
            logging.info(f"🗑 Dropped entire {ts_field} (no rows left after filtering)")

    return df

# ---------------- MAIN ---------------- #
if __name__ == "__main__":
    logging.info("🔎 Starting correlation process...")
    
    # Check snapshot of alert
    alert_snapshot_path = './snapshot/alert_snapshot.json'
    current_alert_snapshot = {'alert_mtime': get_alert_snapshot(alert_output_path)}
    previous_alert_snapshot = load_snapshot(alert_snapshot_path)

    if current_alert_snapshot == previous_alert_snapshot:
        logging.info('✅ No changes in alert file. Skipping correlation process.')
        exit(0)
    else:
        logging.info('⚠ Detected changes in alert file. Proceeding with correlation.')


    # Load Alerts
    alert_df = load_alerts(alert_output_path)
    if alert_df is None or alert_df.empty:
        logging.error("❌ No alert data found.")
        exit(1)

    # Load Zeek log
    zeek_logs = {t: load_zeek_logs(t, local_zeek_log_path, zeek_log_fields) for t in zeek_log_types}
    if zeek_logs["conn"].empty:
        logging.error("❌ No Zeek conn logs found.")
        exit(1)

    # Cordination Alerts w Zeek log
    correlated_df = enrich_alerts_with_zeek(alert_df, zeek_logs["conn"])
    for log_type in zeek_log_types:
        if log_type == "conn":
            continue
        correlated_df = enrich_with_uid(correlated_df, zeek_logs[log_type], name=log_type)
    
    # Remove duplicated IP/port fields if identical to conn.log
    correlated_df = deduplicate_ip_port_fields(correlated_df)
    correlated_df = deduplicate_ts_by_threshold_rowwise(correlated_df, threshold_sec=1)

    # Output to CSV
    correlated_df.to_csv(correlated_output_path, index=False)
    logging.info(f"✅ Correlation complete. Enriched alerts saved to {correlated_output_path}")
    
    save_snapshot(current_alert_snapshot, alert_snapshot_path)
    logging.info('✅ Updated alert snapshot file.')
