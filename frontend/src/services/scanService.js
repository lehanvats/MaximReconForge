// Real scan API — talks to the FastAPI backend (localhost mode). Replaces the
// old dummy scan simulation: engagements are created server-side, progress is
// streamed over a WebSocket, and the final markdown report is fetched here.

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || "http://localhost:8000";

function wsBaseUrl() {
  // Reuse the API origin, swapping the scheme for ws/wss.
  return API_BASE_URL.replace(/^http/i, "ws");
}

async function request(path, options = {}) {
  const response = await fetch(`${API_BASE_URL}${path}`, {
    ...options,
    credentials: "include",
    headers: {
      "Content-Type": "application/json",
      ...options.headers,
    },
  });

  if (!response.ok) {
    let detail = response.statusText;
    try {
      const body = await response.json();
      detail = body.detail || detail;
    } catch {
      // no JSON body
    }
    const error = new Error(detail);
    error.status = response.status;
    throw error;
  }

  if (response.status === 204) {
    return null;
  }

  return response.json();
}

// Create a new engagement. The backend validates scope, persists it, and
// (in localhost mode) immediately starts running the recon graph inline.
export function createEngagement(target) {
  return request("/engagements", {
    method: "POST",
    body: JSON.stringify({ target_domain: target }),
  });
}

// Fetch the rendered markdown report. 404 until the reporting phase finishes.
export function getReport(engagementId) {
  return request(`/engagements/${engagementId}/report`, { method: "GET" });
}

// Fetch the structured findings that back the results dashboard.
export function getFindings(engagementId) {
  return request(`/engagements/${engagementId}/findings`, { method: "GET" });
}

// Direct link for downloading the raw .md — the browser sends the auth cookie
// automatically since it's the same registrable domain as the backend.
export function reportDownloadUrl(engagementId) {
  return `${API_BASE_URL}/engagements/${engagementId}/report/download`;
}

// Open the live event stream for an engagement. Returns a WebSocket.
export function openLiveSocket(engagementId) {
  return new WebSocket(`${wsBaseUrl()}/ws/engagements/${engagementId}/live`);
}
