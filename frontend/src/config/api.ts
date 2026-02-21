/**
 * API Configuration
 *
 * For PRODUCTION: Set VITE_API_URL environment variable
 * Example: VITE_API_URL=https://your-production-server.com
 *
 * For LOCAL: Uses localhost:8000 by default
 */

// Get API URL from environment variable or use production URL as fallback
export const API_URL = import.meta.env.VITE_API_URL || 'https://backend-production-ee900.up.railway.app';

// Export individual parts for flexibility
export const API_BASE = API_URL;
export const API_ENDPOINT = `${API_URL}/api`;

// Helper to build full API URLs
export const apiUrl = (path: string) => `${API_URL}${path.startsWith('/') ? path : '/' + path}`;

export default API_URL;
// Build trigger: 1771709630
