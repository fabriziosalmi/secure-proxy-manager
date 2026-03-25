import axios from 'axios';

// Create an Axios instance
export const api = axios.create({
  baseURL: '/api',
  timeout: 120000,
});

// Add a response interceptor to handle common errors
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response) {
      if (error.response.status === 401) {
        // If unauthorized, the browser's basic auth prompt usually handles this, 
        // but we can catch it here if we want custom behavior.
        console.error('Unauthorized access');
      }
    }
    return Promise.reject(error);
  }
);
