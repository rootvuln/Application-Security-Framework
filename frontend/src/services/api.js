import API_URL from "../config/api";

const API_BASE_URL = `${API_URL}/api`;
const REQUEST_TIMEOUT_MS = 30_000;

export function getErrorMessage(status, errorData) {
  const detail = errorData?.detail;
  const backendMessage =
    typeof detail === "string"
      ? detail
      : Array.isArray(detail)
        ? detail.map((item) => item.msg || String(item)).join(", ")
        : errorData?.message;

  if (backendMessage) {
    return backendMessage;
  }

  const statusMessages = {
    400: "The request was invalid. Check the supplied input.",
    401: "Authentication is required for this request.",
    403: "You are not authorized to perform this request.",
    404: "The requested API resource was not found.",
    500: "The backend encountered an internal error.",
  };

  return statusMessages[status] || `Request failed (${status})`;
}

async function parseResponse(response) {
  const text = await response.text();
  if (!text) {
    return null;
  }

  try {
    return JSON.parse(text);
  } catch {
    throw new Error("The backend returned an invalid response.");
  }
}

export async function apiClient(endpoint, options = {}) {
  const { headers, signal, ...rest } = options;
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

  const config = {
    ...rest,
    signal: signal || controller.signal,
    credentials: "include", // Preserves cybersuite_session cookies & CORS auth
    headers: {
      "Content-Type": "application/json",
      ...headers,
    },
  };

  let response;
  try {
    response = await fetch(`${API_BASE_URL}${endpoint}`, config);
  } catch (error) {
    if (error.name === "AbortError") {
      throw new Error("The request timed out. Please try again.", { cause: error });
    }
    throw new Error(
      "The backend is unavailable. Check your connection and try again.",
      { cause: error },
    );
  } finally {
    clearTimeout(timeoutId);
  }

  const responseData = await parseResponse(response);
  if (!response.ok) {
    throw new Error(getErrorMessage(response.status, responseData));
  }

  return responseData;
}
