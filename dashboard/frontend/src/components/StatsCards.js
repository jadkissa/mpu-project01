import React from "react";

function StatCard({ title, value, color }) {
    return (
        <div style={{
            background: color,
            borderRadius: "10px",
            padding: "20px",
            color: "white",
            textAlign: "center",
            flex: 1,
            minWidth: "150px"
        }}>
            <h2 style={{ margin: 0, fontSize: "2rem" }}>{value}</h2>
            <p style={{ margin: "8px 0 0 0", fontSize: "0.9rem" }}>{title}</p>
        </div>
    );
}

function StatsCards({ stats }) {
    if (!stats) return <p>Loading stats...</p>;
    return (
        <div style={{ display: "flex", gap: "16px", flexWrap: "wrap" }}>
            <StatCard title="Snort Alerts"   value={stats.total_snort_alerts} color="#e74c3c" />
            <StatCard title="ML Detections"  value={stats.total_ml_alerts}    color="#8e44ad" />
            <StatCard title="High Threats"   value={stats.high_threats}       color="#c0392b" />
            <StatCard title="Medium Threats" value={stats.medium_threats}     color="#e67e22" />
        </div>
    );
}

export default StatsCards;