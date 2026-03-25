import axios from 'axios';

export const api = axios.create({
  baseURL: '/api',
  timeout: 120000,
});

// Attach JWT Bearer token from sessionStorage to every request
api.interceptors.request.use((config) => {
  const token = sessionStorage.getItem('auth_token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// On 401, clear the stale token and reload so the Login page appears
api.interceptors.response.use(
  (response) => response,
  (error: unknown) => {
    if (axios.isAxiosError(error) && error.response?.status === 401) {
      sessionStorage.removeItem('auth_token');
      window.location.reload();
    }
    return Promise.reject(error);
  }
);

/** Extract a human-readable message from an Axios error, with a fallback. */
export function getErrorMessage(err: unknown, fallback: string): string {
  if (axios.isAxiosError(err)) {
    return (
      (err.response?.data as { message?: string; detail?: string })?.message ??
      (err.response?.data as { message?: string; detail?: string })?.detail ??
      fallback
    );
  }
  return fallback;
}
