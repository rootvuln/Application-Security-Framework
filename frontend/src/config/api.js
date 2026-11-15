const API_URL = import.meta.env.VITE_API_URL;

if (!API_URL) {
  throw new Error("VITE_API_URL environment variable is missing");
}

export default API_URL.replace(/\/+$/, "");
