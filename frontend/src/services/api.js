/**
 * Base API client for CyberSuite
 * Communicates with the FastAPI backend (/api)
 */
const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || "/api";

export async function apiClient(endpoint, options = {}) {
  const { headers, ...rest } = options;

  const config = {
    ...rest,
    credentials: "include", // Preserves cybersuite_session cookies & CORS auth
    headers: {
      "Content-Type": "application/json",
      ...headers,
    },
  };

  const response = await fetch(`${API_BASE_URL}${endpoint}`, config);

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    const message = errorData.detail || errorData.message || `Request failed (${response.status})`;
    throw new Error(message);
  }

  return response.json();
}
