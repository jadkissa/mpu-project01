import React from "react";

function SnortAlerts({ alerts }) {
    if (!alerts) return <p>Loading alerts...</p>;
    return (
        <div>
            <h3>Snort Alerts</h3>
            <table style={{ width: "100%", borderCollapse: "collapse" }}>
                <thead>
                    <tr style={{ background: "#2c3e50", color: "white" }}>
                        <th style={th}>Time</th>
                        <th style={th}>Src IP</th>
                        <th style={th}>Dst IP</th>
                        <th style={th}>Protocol</th>
                        <th style={th}>Message</th>
                        <th style={th}>Priority</th>
                    </tr>
                </thead>
                <tbody>
                    {alerts.length === 0 ? (
                        <tr>
                            <td colSpan={6} style={{ textAlign: "center", padding: "20px" }}>
                                No alerts yet
                            </td>
                        </tr>
                    ) : (
                        alerts.map(a => (
                            <tr key={`${a.sid}-${a.cid}`} style={{ borderBottom: "1px solid #eee" }}>
                                <td style={td}>{new Date(a.timestamp).toLocaleString()}</td>
                                <td style={td}>{a.ip_src}</td>
                                <td style={td}>{a.ip_dst}</td>
                                <td style={td}>
                                    {a.ip_proto === 6 ? "TCP" : a.ip_proto === 17 ? "UDP" : a.ip_proto === 1 ? "ICMP" : a.ip_proto}
                                </td>
                                <td style={td}>{a.sig_name}</td>
                                <td style={td}>
                                    <span style={{
                                        background: a.priority === 1 ? "#e74c3c" : a.priority === 2 ? "#e67e22" : "#27ae60",
                                        color: "white",
                                        padding: "2px 8px",
                                        borderRadius: "4px",
                                        fontSize: "0.8rem"
                                    }}>
                                        {a.priority === 1 ? "High" : a.priority === 2 ? "Medium" : "Low"}
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

export default SnortAlerts;