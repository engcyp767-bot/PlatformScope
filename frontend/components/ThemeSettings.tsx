'use client';

import { useEffect } from 'react';
import { fetchApi } from '../lib/api';

export type Appearance = {
  theme?: string; primary_color?: string; accent_color?: string;
  compact_mode?: boolean; animations?: boolean; platform_title?: string;
};

const rgb = (hex: string, fallback: string) => {
  const value = /^#[0-9a-f]{6}$/i.test(hex || '') ? hex : fallback;
  return `${parseInt(value.slice(1, 3), 16)} ${parseInt(value.slice(3, 5), 16)} ${parseInt(value.slice(5, 7), 16)}`;
};

export function applyAppearance(appearance: Appearance) {
  const root = document.documentElement;
  root.dataset.theme = appearance.theme || 'dark';
  root.dataset.compact = appearance.compact_mode ? 'true' : 'false';
  root.dataset.animations = appearance.animations === false ? 'false' : 'true';
  root.style.setProperty('--primary-rgb', rgb(appearance.primary_color || '', '#6366f1'));
  root.style.setProperty('--primary-hover-rgb', rgb(appearance.primary_color || '', '#818cf8'));
  root.style.setProperty('--accent-rgb', rgb(appearance.accent_color || '', '#ff4d8d'));
  if (appearance.platform_title) document.title = appearance.platform_title;
  localStorage.setItem('platform-appearance', JSON.stringify(appearance));
}

export function ThemeSettings() {
  useEffect(() => {
    const apply = () => fetchApi('/api/settings/public').then((response) => applyAppearance(response.appearance || {})).catch(() => {});
    const onUpdate = (event: Event) => {
      const appearance = (event as CustomEvent<Appearance>).detail;
      if (appearance) applyAppearance(appearance); else apply();
    };
    apply();
    window.addEventListener('platform-config-updated', onUpdate);
    return () => window.removeEventListener('platform-config-updated', onUpdate);
  }, []);
  return null;
}

export function PlatformAtmosphere() {
  return <div className="platform-atmosphere" aria-hidden="true"><i /><i /><i /><span /></div>;
}
