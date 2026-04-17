import React from "react";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from "recharts";

function ProtocolChart({ data }) {
  if (!data || data.length === 0) return <p>No protocol data yet</p>;

  return (
    <div>
      <h3>Alerts by Protocol</h3>
      <ResponsiveContainer width="100%" height={300}>
        <BarChart data={data}>
          <CartesianGrid strokeDasharray="3 3" />
          <XAxis dataKey="protocol" />
          <YAxis />
          <Tooltip />
          <Bar dataKey="count" fill="#2c3e50" />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

export default ProtocolChart;
