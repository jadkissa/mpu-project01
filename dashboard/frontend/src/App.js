import React, { useState, useEffect } from "react";
import StatsCards from "./components/StatsCards";
import SnortAlerts from "./components/SnortAlerts";
import MLDetections from "./components/MLDetections";
import ProtocolChart from "./components/ProtocolChart";
import {
  getSummary,
  getSnortAlerts,
  getMLDetections,
  getByProtocol,
} from "./api";

function App() {
  const [stats, setStats] = useState(null);
  const [snort, setSnort] = useState([]);
  const [ml, setML] = useState([]);
  const [protocols, setProtocols] = useState([]);

  const fetchData = async () => {
    try {
      const [s, sn, ml_, pr] = await Promise.all([
        getSummary(),
        getSnortAlerts(),
        getMLDetections(),
        getByProtocol(),
      ]);
      setStats(s.data);
      setSnort(sn.data.data);
      setML(ml_.data.data);
      setProtocols(pr.data.data);
    } catch (err) {
      console.error("API error:", err);
    }
  };

  // جلب البيانات عند البداية وكل 0.5 ثانية
  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 500);
    return () => clearInterval(interval);
  }, []);

  return (
    <div
      style={{
        padding: "24px",
        fontFamily: "sans-serif",
        background: "#f5f6fa",
        minHeight: "100vh",
      }}
    >
      <h1 style={{ marginBottom: "24px" }}>NIDS Dashboard</h1>

      <StatsCards stats={stats} />

      <div
        style={{
          marginTop: "32px",
          background: "white",
          padding: "20px",
          borderRadius: "10px",
        }}
      >
        <ProtocolChart data={protocols} />
      </div>

      <div
        style={{
          marginTop: "24px",
          background: "white",
          padding: "20px",
          borderRadius: "10px",
        }}
      >
        <SnortAlerts alerts={snort} />
      </div>

      <div
        style={{
          marginTop: "24px",
          background: "white",
          padding: "20px",
          borderRadius: "10px",
        }}
      >
        <MLDetections detections={ml} />
      </div>
    </div>
  );
}

export default App;
