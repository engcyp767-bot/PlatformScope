import { LucideIcon } from 'lucide-react';

export type SettingsTabId =
  | 'overview'
  | 'general'
  | 'appearance'
  | 'users'
  | 'security'
  | 'ai'
  | 'ollama'
  | 'analysis'
  | 'uploads'
  | 'sources'
  | 'integrations'
  | 'reports'
  | 'storage'
  | 'logging'
  | 'features'
  | 'network'
  | 'governance'
  | 'maintenance';

export interface SettingsNavChild {
  id: SettingsTabId;
  label: string;
  badge?: string;
  isRestartRequired?: boolean;
  helpAnchor?: string;
}

export interface SettingsNavGroup {
  id: string;
  title: string;
  icon: LucideIcon;
  children: SettingsNavChild[];
}

export interface SettingsSearchIndexItem {
  tabId: SettingsTabId;
  fieldId?: string;
  title: string;
  category: string;
  keywords: string[];
  description: string;
}
