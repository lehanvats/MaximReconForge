const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || "http://localhost:8000";

// Demo account — works even when the backend is offline.
const DEMO_EMAIL = "test@maximrecon.com";
const DEMO_PASSWORD = "test1234";
const DEMO_PROFILE = { id: "demo", email: DEMO_EMAIL, username: "test" };

function _setStoredSession(profile) {
  sessionStorage.setItem("demo_user", JSON.stringify(profile));
}

export function getStoredSession() {
  try {
    return JSON.parse(sessionStorage.getItem("demo_user"));
  } catch {
    return null;
  }
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
      // response had no JSON body
    }
    throw new Error(detail);
  }

  if (response.status === 204) {
    return null;
  }

  return response.json();
}

// The backend sets the access/refresh JWTs as httpOnly cookies on these
// calls — the browser stores and replays them automatically, so the
// response body only ever contains the user profile, never the tokens.
export function register(email, password) {
  return request("/auth/register", {
    method: "POST",
    body: JSON.stringify({ email, password }),
  });
}

export async function login(email, password) {
  try {
    const user = await request("/auth/login", {
      method: "POST",
      body: JSON.stringify({ email, password }),
    });
    sessionStorage.removeItem("demo_user");
    return user;
  } catch (err) {
    // If backend login fails for demo credentials, fallback to client session
    if (email === DEMO_EMAIL && password === DEMO_PASSWORD) {
      _setStoredSession(DEMO_PROFILE);
      return DEMO_PROFILE;
    }
    throw err;
  }
}

export function logout() {
  sessionStorage.removeItem("demo_user");
  return request("/auth/logout", { method: "POST" });
}

export function fetchCurrentUser() {
  return request("/auth/me", { method: "GET" }).catch((err) => {
    const demo = getStoredSession();
    if (demo) return demo;
    throw err;
  });
}
