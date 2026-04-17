import axios from "axios";

const API = axios.create({
    baseURL: "http://localhost:8000"
});

export const getSnortAlerts  = () => API.get("/api/alerts/snort");
export const getMLDetections = () => API.get("/api/alerts/ml");
export const getThreats      = () => API.get("/api/alerts/ml/threats");
export const getSummary      = () => API.get("/api/stats/summary");
export const getByProtocol   = () => API.get("/api/stats/by-protocol");