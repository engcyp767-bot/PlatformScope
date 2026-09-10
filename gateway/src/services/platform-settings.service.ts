import fs from 'fs';
import path from 'path';

import { STORAGE_DIR } from '../config.js';

export type FeatureName = 'flowscope_enabled' | 'threatscope_enabled' | 'logscope_enabled' | 'report_preview' | 'excel_export' | 'force_refresh' | 'analyst_feedback';

const DEFAULTS: Record<FeatureName, boolean> = {
  flowscope_enabled: true,
  threatscope_enabled: true,
  logscope_enabled: true, report_preview: true,
  excel_export: true, force_refresh: true, analyst_feedback: true,
};
const SETTINGS_FILE = path.join(STORAGE_DIR, 'platform_config.json');
let cachedMtime = -1;
let cachedFeatures = { ...DEFAULTS };

export function platformFeatures(): Record<FeatureName, boolean> {
  try {
    const mtime = fs.statSync(SETTINGS_FILE).mtimeMs;
    if (mtime !== cachedMtime) {
      const stored = JSON.parse(fs.readFileSync(SETTINGS_FILE, 'utf8'))?.features || {};
      cachedFeatures = Object.fromEntries(Object.entries(DEFAULTS).map(([key, fallback]) => [key, typeof stored[key] === 'boolean' ? stored[key] : fallback])) as Record<FeatureName, boolean>;
      cachedMtime = mtime;
    }
  } catch { cachedFeatures = { ...DEFAULTS }; }
  return { ...cachedFeatures };
}
