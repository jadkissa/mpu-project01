import React from "react";

function MLDetections({ detections }) {
    if (!detections) return <p>Loading detections...</p>;

    const verdictColor = {
        HIGH_THREAT:   "#e74c3c",
        MEDIUM_THREAT: "#e67e22",
        NORMAL:        "#27ae60"
    };

    return (
        <div>
            <h3>ML Detections</h3>
            <table style={{ width: "100%", borderCollapse: "collapse" }}>
                <thead>
                    <tr style={{ background: "#2c3e50", color: "white" }}>
                        <th style={th}>Time</th>
                        <th style={th}>Src IP</th>
                        <th style={th}>Dst IP</th>
                        <th style={th}>Protocol</th>
                        <th style={th}>Anomaly Score</th>
                        <th style={th}>Confidence</th>
                        <th style={th}>Verdict</th>
                    </tr>
                </thead>
                <tbody>
                    {detections.length === 0 ? (
                        <tr>
                            <td colSpan={7} style={{ textAlign: "center", padding: "20px" }}>
                                No detections yet
                            </td>
                        </tr>
                    ) : (
                        detections.map(d => (
                            <tr key={d.id} style={{ borderBottom: "1px solid #eee" }}>
                                <td style={td}>{new Date(d.timestamp).toLocaleString()}</td>
                                <td style={td}>{d.src_ip}</td>
                                <td style={td}>{d.dst_ip}</td>
                                <td style={td}>{d.protocol}</td>
                                <td style={td}>{d.anomaly_score?.toFixed(3)}</td>
                                <td style={td}>{d.confidence != null ? (d.confidence * 100).toFixed(1) + "%" : "-"}</td>
                                <td style={td}>
                                    <span style={{
                                        background: verdictColor[d.verdict] || "#95a5a6",
                                        color: "white",
                                        padding: "2px 8px",
                                        borderRadius: "4px",
                                        fontSize: "0.8rem"
                                    }}>
                                        {d.verdict}
                                    </span>
                                </td>
                            </tr>
                        ))
                    )}
                </tbody>
            </table>
        </div>
    );
}

const th = { padding: "10px", textAlign: "left" };
const td = { padding: "8px 10px" };

export default MLDetections;