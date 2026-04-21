import os
import time
import joblib
import numpy as np
import psycopg2
from datetime import datetime, timedelta
from collections import defaultdict
from scapy.all import sniff, IP, TCP, UDP
from sklearn.ensemble import IsolationForest

# ─── Config ───────────────────────────────────────────
INTERFACE      = os.getenv("INTERFACE", "wlp4s0")
DB_HOST        = os.getenv("DB_HOST", "postgres")
DB_PORT        = os.getenv("DB_PORT", "5432")
DB_NAME        = os.getenv("DB_NAME", "mpu_db")
DB_USER        = os.getenv("DB_USER", "mpu")
DB_PASSWORD    = os.getenv("DB_PASSWORD", "123")
MODEL_PATH     = "/app/models/model.pkl"
TRAINING_TIME  = int(os.getenv("TRAINING_TIME", "900"))  # 15 دقيقة
FLOW_WINDOW    = 10   # ثواني لتجميع الـ flow
SNORT_WINDOW   = 10   # ثواني للمقارنة مع سنورت

# ─── Database ─────────────────────────────────────────
def get_db():
    return psycopg2.connect(
        host=DB_HOST, port=DB_PORT,
        dbname=DB_NAME, user=DB_USER, password=DB_PASSWORD
    )

# ─── هل سنورت اكتشف هالـ flow؟ ──────────────────────
def detected_by_snort(conn, src_ip, dst_ip, dport, proto):
    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT COUNT(*) FROM event
            WHERE ip_src = %s
            AND ip_dst = %s
            AND layer4_dport = %s
            AND ip_proto = %s
            AND timestamp > NOW() - INTERVAL '%s seconds'
        """, (src_ip, dst_ip, dport, proto, SNORT_WINDOW))
        count = cur.fetchone()[0]
        cur.close()
        return count > 0
    except:
        return False

# ─── سجل في ml_alerts ────────────────────────────────
def save_alert(conn, src_ip, dst_ip, proto, score, verdict):
    try:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO ml_alerts 
            (timestamp, src_ip, dst_ip, protocol, anomaly_score, confidence, verdict)
            VALUES (NOW(), %s::inet, %s::inet, %s, %s, %s, %s)
        """, (src_ip, dst_ip, proto, float(score),
              float(abs(score)), verdict))
        conn.commit()
        cur.close()
        print(f"[ML ALERT SAVED] {verdict} | {src_ip} → {dst_ip}")
    except Exception as e:
        print(f"[DB ERROR] {e}")
        conn.rollback()

# ─── استخرج features من flow ─────────────────────────
def extract_features(flow):
    packets     = flow['packets']
    sizes       = flow['sizes']
    duration    = flow['duration']
    syn_count   = flow['syn_count']
    unique_dsts = flow['unique_dsts']
    unique_ports = flow['unique_ports']

    return [
        len(packets),                                          # packet_count
        sum(sizes),                                            # total_bytes
        np.mean(sizes) if sizes else 0,                        # avg_packet_size
        duration,                                              # duration
        len(packets) / max(duration, 1),                       # packets_per_second
        syn_count,                                             # syn_count
        len(unique_dsts),                                      # unique_dst_ips
        len(unique_ports),                                     # unique_dst_ports
    ]

# ─── تجميع الـ flows ──────────────────────────────────
flows = defaultdict(lambda: {
    'packets': [], 'sizes': [], 'syn_count': 0,
    'unique_dsts': set(), 'unique_ports': set(),
    'start_time': time.time(), 'duration': 0,
    'src_ip': '', 'dst_ip': '', 'proto': ''
})

def process_packet(pkt):
    if not pkt.haslayer(IP):
        return

    src = pkt[IP].src
    dst = pkt[IP].dst
    size = len(pkt)
    proto = pkt[IP].proto
    dport = 0

    if pkt.haslayer(TCP):
        dport = pkt[TCP].dport
        if pkt[TCP].flags & 0x02:  # SYN flag
            flows[src]['syn_count'] += 1
    elif pkt.haslayer(UDP):
        dport = pkt[UDP].dport

    flows[src]['packets'].append(time.time())
    flows[src]['sizes'].append(size)
    flows[src]['unique_dsts'].add(dst)
    flows[src]['unique_ports'].add(dport)
    flows[src]['src_ip'] = src
    flows[src]['dst_ip'] = dst
    flows[src]['proto'] = str(proto)
    flows[src]['duration'] = time.time() - flows[src]['start_time']

# ─── Training Mode ────────────────────────────────────
def train_model():
    print(f"[TRAINING] Collecting normal traffic for {TRAINING_TIME} seconds...")
    print("[TRAINING] Make sure NO attacks are happening now!")

    training_data = []
    start = time.time()

    def collect(pkt):
        process_packet(pkt)

    # جمع الترافيك
    while time.time() - start < TRAINING_TIME:
        sniff(iface=INTERFACE, prn=collect, timeout=FLOW_WINDOW, store=False)

        for src_ip, flow in list(flows.items()):
            if len(flow['packets']) >= 3:
                features = extract_features(flow)
                training_data.append(features)

        flows.clear()
        elapsed = int(time.time() - start)
        print(f"[TRAINING] {elapsed}/{TRAINING_TIME}s — {len(training_data)} flows collected")

    if len(training_data) < 10:
        print("[TRAINING] Not enough data! Need at least 10 flows. Try again.")
        return None

    print(f"[TRAINING] Training Isolation Forest on {len(training_data)} flows...")
    model = IsolationForest(
        n_estimators=100,
        contamination=0.05,  # 5% من الترافيك ممكن يكون شاذ
        random_state=42
    )
    model.fit(training_data)
    joblib.dump(model, MODEL_PATH)
    print(f"[TRAINING] Model saved to {MODEL_PATH}")
    return model

# ─── Detection Mode ───────────────────────────────────
def detect(model, conn):
    print(f"[DETECTION] Monitoring {INTERFACE} for anomalies...")

    def capture(pkt):
        process_packet(pkt)

    while True:
        sniff(iface=INTERFACE, prn=capture, timeout=FLOW_WINDOW, store=False)

        for src_ip, flow in list(flows.items()):
            if len(flow['packets']) < 3:
                continue

            features = extract_features(flow)
            score = model.score_samples([features])[0]
            prediction = model.predict([features])[0]

            # anomaly = -1, normal = 1
            if prediction == -1:
                dst_ip = flow['dst_ip']
                dport  = list(flow['unique_ports'])[0] if flow['unique_ports'] else 0
                proto  = flow['proto']

                # هل سنورت اكتشفها؟
                if detected_by_snort(conn, src_ip, dst_ip, dport, proto):
                    print(f"[SKIP] Already detected by Snort: {src_ip} → {dst_ip}")
                else:
                    # ML بس اكتشفها
                    if score < -0.3:
                        verdict = "HIGH_THREAT"
                    else:
                        verdict = "MEDIUM_THREAT"

                    save_alert(conn, src_ip, dst_ip, proto, score, verdict)

        flows.clear()

# ─── Main ─────────────────────────────────────────────
def main():
    print("[ML ENGINE] Starting...")

    # انتظر قاعدة البيانات
    conn = None
    for i in range(10):
        try:
            conn = get_db()
            print("[ML ENGINE] Database connected")
            break
        except:
            print(f"[ML ENGINE] Waiting for database... ({i+1}/10)")
            time.sleep(5)

    if conn is None:
        print("[ML ENGINE] Cannot connect to database. Exiting.")
        return

    # تدريب أو تحميل الموديل
    if os.path.exists(MODEL_PATH):
        print("[ML ENGINE] Loading existing model...")
        model = joblib.load(MODEL_PATH)
        print("[ML ENGINE] Model loaded — entering detection mode")
    else:
        print("[ML ENGINE] No model found — entering training mode")
        model = train_model()
        if model is None:
            return

    # ابدأ الكشف
    detect(model, conn)

if __name__ == "__main__":
    main()
