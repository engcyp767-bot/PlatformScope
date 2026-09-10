import { PYTHON_BACKEND_URL } from '../config.js';

export interface LicenseStatus {
  state: string;
  license_type: string;
  product: string;
  edition: string;
  installation_id: string;
  instance_id: string;
  start_utc: string;
  expires_utc: string;
  days_remaining: number;
  grace_days: number;
  is_valid: boolean;
  status_message: string;
  customer_org: string;
  license_id: string;
  entitlements: {
    features: string[];
    max_users: number;
    max_assets: number;
    max_daily_events: number;
  };
}

let cachedStatus: LicenseStatus | null = null;
let lastFetchTime = 0;
const CACHE_TTL_MS = 15_000;

export async function fetchLicenseStatus(forceRefresh = false): Promise<LicenseStatus | null> {
  const now = Date.now();
  if (!forceRefresh && cachedStatus && (now - lastFetchTime < CACHE_TTL_MS)) {
    return cachedStatus;
  }

  try {
    const res = await fetch(`${PYTHON_BACKEND_URL}/api/licensing/status`, {
      signal: AbortSignal.timeout(3_000),
    });
    if (res.ok) {
      cachedStatus = await res.json() as LicenseStatus;
      lastFetchTime = now;
      return cachedStatus;
    }
  } catch {
    // If backend is momentarily unreachable, return stale cache if available
  }
  return cachedStatus;
}

export function invalidateLicenseCache(): void {
  cachedStatus = null;
  lastFetchTime = 0;
}

