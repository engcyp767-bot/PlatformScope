'use client';

import React, { createContext, useContext, useEffect, useState } from 'react';
import ar from '../locales/ar.json';
import en from '../locales/en.json';
import { fetchApi } from './api';

export type Language = 'ar' | 'en';
export type Dictionary = typeof ar;

type I18nContextType = {
  lang: Language;
  dir: 'ltr' | 'rtl';
  t: (key: string, fallback?: string) => string;
  setLang: (lang: Language) => void;
};

const dictionaries: Record<Language, any> = { ar, en };

const I18nContext = createContext<I18nContextType | null>(null);

export function useTranslation() {
  const context = useContext(I18nContext);
  if (!context) {
    throw new Error('useTranslation must be used within an I18nProvider');
  }
  return context;
}

export function I18nProvider({ children }: { children: React.ReactNode }) {
  const [lang, setLangState] = useState<Language>('ar');

  const setLang = (newLang: Language) => {
    setLangState(newLang);
    document.documentElement.lang = newLang;
    document.documentElement.dir = dictionaries[newLang].dir;
  };

  useEffect(() => {
    // Initial fetch
    fetchApi('/api/settings/public')
      .then((res) => {
        if (res?.general?.language === 'en') {
          setLang('en');
        } else {
          setLang('ar');
        }
      })
      .catch(() => {});

    // Listen to changes from settings page
    const handleUpdate = () => {
      fetchApi('/api/settings/public')
        .then((res) => {
          if (res?.general?.language === 'en') {
            setLang('en');
          } else {
            setLang('ar');
          }
        })
        .catch(() => {});
    };

    window.addEventListener('platform-config-updated', handleUpdate);
    return () => window.removeEventListener('platform-config-updated', handleUpdate);
  }, []);

  const t = (path: string, fallback?: string): string => {
    const keys = path.split('.');
    let current: any = dictionaries[lang];
    for (const key of keys) {
      if (current[key] === undefined) {
        return fallback || path;
      }
      current = current[key];
    }
    return current;
  };

  return (
    <I18nContext.Provider value={{ lang, dir: dictionaries[lang].dir as 'ltr' | 'rtl', t, setLang }}>
      {children}
    </I18nContext.Provider>
  );
}
