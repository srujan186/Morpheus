const BASE_URL = "http://localhost:8000";

export const startScan = async () => {
  const res = await fetch(`${BASE_URL}/scan`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ agent: "vulnerable_agent_1" })
  });
  return res.json();
};

export const getScanStatus = async (scanId) => {
  const res = await fetch(`${BASE_URL}/scan/status/${scanId}`);
  return res.json();
};

export const getReport = async (scanId) => {
  const res = await fetch(`${BASE_URL}/scan/result/${scanId}`);
  return res.json();
};