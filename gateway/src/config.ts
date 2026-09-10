import path from 'path';
import dotenv from 'dotenv';

dotenv.config();

export const WORKSPACE_ROOT = path.resolve(__dirname, '../../');
export const STORAGE_DIR = path.join(WORKSPACE_ROOT, 'storage');
export const AUDIT_DIR = path.join(STORAGE_DIR, 'audit');
export const AUTH_FILE = path.join(STORAGE_DIR, 'security_auth.json');
export const FLOWSCOPE_JOBS_DIR = path.join(WORKSPACE_ROOT, 'flowscope', 'storage', 'jobs');
export const THREATSCOPE_JOBS_DIR = path.join(WORKSPACE_ROOT, 'threatscope', 'storage', 'jobs');
export const LOGSCOPE_JOBS_DIR = path.join(WORKSPACE_ROOT, 'logscope', 'storage', 'jobs');

export const HOST = process.env.SECURITY_GATEWAY_HOST || '127.0.0.1';
export const PORT = parseInt(process.env.SECURITY_GATEWAY_PORT || '8081', 10);
export const PYTHON_BACKEND_URL = process.env.PYTHON_BACKEND_URL || 'http://127.0.0.1:8082';
export const COOKIE_NAME = 'security_session';
export const SESSION_SECONDS = Math.max(900, parseInt(process.env.SECURITY_SESSION_HOURS || '12', 10) * 3600);
export const SECURE_COOKIE = /^(1|true|yes|on)$/i.test(process.env.SECURITY_SECURE_COOKIE || 'false');
export const PROXY_TIMEOUT_MS = Math.max(10, parseInt(process.env.SECURITY_PROXY_TIMEOUT_SECONDS || '300', 10)) * 1000;

export const ALLOWED_ORIGINS = [
  'http://192.168.88.66:3000',
  'http://127.0.0.1:3000',
  'http://localhost:3000',
  ...(process.env.SECURITY_ALLOWED_ORIGINS || '').split(',').map((item) => item.trim()).filter(Boolean),
].filter((value, index, values) => values.indexOf(value) === index);
