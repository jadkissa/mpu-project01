from fastapi import APIRouter
from database import query

router = APIRouter()

@router.get("/snort")
def get_snort_alerts(limit: int = 50):
    rows = query("""
        SELECT
            e.sid,
            e.cid,
            e.signature,
            e.timestamp,
            host(e.ip_src) AS ip_src,
            host(e.ip_dst) AS ip_dst,
            e.layer4_sport,
            e.layer4_dport,
            e.ip_proto,
            e.priority,
            s.sig_name
        FROM event e
        LEFT JOIN signature s ON s.sig_sid = e.signature_id
        ORDER BY e.timestamp DESC
        LIMIT %s
    """, (limit,))
    return {"data": rows}

@router.get("/ml")
def get_ml_alerts(limit: int = 50):
    rows = query("""
        SELECT
            id,
            timestamp,
            host(src_ip) AS src_ip,
            host(dst_ip) AS dst_ip,
            protocol,
            anomaly_score,
            confidence,
            verdict
        FROM ml_alerts
        ORDER BY timestamp DESC
        LIMIT %s
    """, (limit,))
    return {"data": rows}

@router.get("/ml/threats")
def get_ml_threats(limit: int = 50):
    rows = query("""
        SELECT
            id,
            timestamp,
            host(src_ip) AS src_ip,
            host(dst_ip) AS dst_ip,
            protocol,
            anomaly_score,
            confidence,
            verdict
        FROM ml_alerts
        WHERE verdict != 'normal'
        ORDER BY timestamp DESC
        LIMIT %s
    """, (limit,))
    return {"data": rows}