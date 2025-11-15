/**
 * API Configuration
 * Uses environment variables for production, falls back to local proxy for development
 */

// Get API URL from environment variable (set in Vercel) or use local proxy
const API_BASE_URL = import.meta.env.VITE_API_URL || '/api';

// WebSocket URL (convert http to ws)
const getWebSocketUrl = () => {
  if (import.meta.env.VITE_API_URL) {
    // Production: convert https:// to wss:// or http:// to ws://
    const wsUrl = import.meta.env.VITE_API_URL
      .replace('https://', 'wss://')
      .replace('http://', 'ws://');
    return wsUrl.replace('/api', '/ws');
  }
  // Development: use proxy
  return '/ws';
};

export const API_BASE = API_BASE_URL;
export const WS_BASE = getWebSocketUrl();

// Helper function to create full API URL
export const getApiUrl = (endpoint) => {
  // Remove leading slash if present to avoid double slashes
  const cleanEndpoint = endpoint.startsWith('/') ? endpoint.slice(1) : endpoint;
  return `${API_BASE}/${cleanEndpoint}`;
};

