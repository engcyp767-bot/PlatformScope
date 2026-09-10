'use client';

import React, { useEffect, useState } from 'react';
import Link from 'next/link';
import { Navbar } from '../components/Navbar';
import { Activity, ShieldAlert, Terminal, ArrowLeft, Shield } from 'lucide-react';
import { User } from '../lib/types';
import { getAuthStatus, getServicesStatus } from '../lib/api';
import { useTranslation } from '../lib/i18n';

export default function HomePage() {
  const { t } = useTranslation();
  const [user, setUser] = useState<User | null>(null);
  const [isAuthenticated, setIsAuthenticated] = useState<boolean | null>(null);
  const [services, setServices] = useState<{ flowscope: boolean; threatscope: boolean; logscope: boolean }>({
    flowscope: false,
    threatscope: false,
    logscope: false,
  });

  useEffect(() => {
    getAuthStatus().then((res) => {
      if (res.authenticated && res.user) {
        setUser(res.user);
        setIsAuthenticated(true);
      } else {
        setIsAuthenticated(false);
        window.location.href = '/login';
      }
    }).catch(() => {
      setIsAuthenticated(false);
      window.location.href = '/login';
    });

    getServicesStatus().then(setServices).catch(() => {});
    const interval = setInterval(() => {
      getServicesStatus().then(setServices).catch(() => {});
    }, 10000);
    return () => clearInterval(interval);
  }, []);

  if (isAuthenticated === null) {
    return (
      <div className="min-h-screen bg-dark-950 flex flex-col items-center justify-center p-4">
        <div className="flex flex-col items-center gap-4 animate-pulse">
          <div className="w-12 h-12 rounded-2xl bg-gradient-to-br from-primary/20 to-accent/20 border border-primary/40 flex items-center justify-center shadow-lg shadow-primary/10">
            <Shield className="w-6 h-6 text-primary" />
          </div>
          <div className="flex items-center gap-2 text-xs text-slate-400 font-heading">
            <div className="w-3.5 h-3.5 border-2 border-primary border-t-transparent rounded-full animate-spin"></div>
            <span>جاري التحقق من الجلسة...</span>
          </div>
        </div>
      </div>
    );
  }

  if (isAuthenticated === false) {
    return null;
  }

  return (
    <div className="min-h-screen flex flex-col">
      <Navbar />

      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-10">
        <div className="platform-hero mb-10 text-center sm:text-right">
          <div className="inline-block px-3 py-1 rounded-full bg-primary/10 border border-primary/30 text-primary text-xs font-semibold uppercase tracking-wider mb-2">
            {t('dashboard.subtitle')}
          </div>
          <h1 className="text-3xl sm:text-4xl font-extrabold text-white tracking-tight">
            {t('dashboard.title')}
          </h1>
          <p className="text-slate-400 mt-2 text-sm sm:text-base max-w-2xl">
            {t('dashboard.desc')}
          </p>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 md:grid-cols-2 gap-6 lg:gap-8">
          {/* FlowScope Card */}
          <Link
            href="/flowscope"
            className="workspace-card glass-panel p-8 group relative overflow-hidden transition-all duration-300 hover:border-cyan-500/50 hover:shadow-2xl hover:shadow-cyan-500/10 flex flex-col justify-between"
          >
            <div className="absolute top-0 right-0 w-32 h-32 bg-cyan-500/10 rounded-full blur-2xl pointer-events-none group-hover:bg-cyan-500/20 transition-colors"></div>
            
            <div>
              <div className="flex items-center justify-between mb-6">
                <div className="w-14 h-14 rounded-2xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400 group-hover:scale-110 group-hover:shadow-lg group-hover:shadow-cyan-500/20 transition-all">
                  <Activity className="w-7 h-7" />
                </div>
                <div className="flex items-center gap-2 px-3 py-1 rounded-full bg-dark-950/60 border border-white/10 text-xs">
                  <div className={`w-2 h-2 rounded-full ${services.flowscope ? 'bg-cyan-400 animate-pulse' : 'bg-slate-500'}`}></div>
                  <span className="text-slate-300 font-medium">
                    {services.flowscope ? t('dashboard.connected') : t('dashboard.ready')}
                  </span>
                </div>
              </div>

              <h2 className="text-2xl font-bold text-white group-hover:text-cyan-400 transition-colors flex items-center gap-2 font-heading">
                FlowScope
              </h2>
              <p className="text-slate-400 text-sm mt-2 leading-relaxed">
                {t('dashboard.flowscope_desc')}
              </p>

              <div className="flex flex-wrap gap-2 mt-6">
                <span className="px-2.5 py-1 rounded-md bg-white/5 border border-white/10 text-slate-300 text-xs font-medium">
                  {t('dashboard.flowscope_tag1')}
                </span>
                <span className="px-2.5 py-1 rounded-md bg-white/5 border border-white/10 text-slate-300 text-xs font-medium">
                  {t('dashboard.flowscope_tag2')}
                </span>
                <span className="px-2.5 py-1 rounded-md bg-white/5 border border-white/10 text-slate-300 text-xs font-medium">
                  {t('dashboard.flowscope_tag3')}
                </span>
              </div>
            </div>

            <div className="mt-8 pt-6 border-t border-white/10 flex items-center justify-between text-cyan-400 text-sm font-bold group-hover:translate-x-[-4px] transition-transform">
              <span>{t('dashboard.flowscope_enter')}</span>
              <ArrowLeft className="w-5 h-5" />
            </div>
          </Link>

          {/* ThreatScope Card */}
          <Link
            href="/threatscope"
            className="workspace-card glass-panel p-8 group relative overflow-hidden transition-all duration-300 hover:border-accent/50 hover:shadow-2xl hover:shadow-accent/10 flex flex-col justify-between"
          >
            <div className="absolute top-0 right-0 w-32 h-32 bg-accent/10 rounded-full blur-2xl pointer-events-none group-hover:bg-accent/20 transition-colors"></div>
            
            <div>
              <div className="flex items-center justify-between mb-6">
                <div className="w-14 h-14 rounded-2xl bg-rose-500/10 border border-rose-500/30 flex items-center justify-center text-rose-400 group-hover:scale-110 group-hover:shadow-lg group-hover:shadow-rose-500/20 transition-all">
                  <ShieldAlert className="w-7 h-7" />
                </div>
                <div className="flex items-center gap-2 px-3 py-1 rounded-full bg-dark-950/60 border border-white/10 text-xs">
                  <div className={`w-2 h-2 rounded-full ${services.threatscope ? 'bg-rose-400 animate-pulse' : 'bg-slate-500'}`}></div>
                  <span className="text-slate-300 font-medium">
                    {services.threatscope ? t('dashboard.connected') : t('dashboard.ready')}
                  </span>
                </div>
              </div>

              <h2 className="text-2xl font-bold text-white group-hover:text-accent transition-colors flex items-center gap-2 font-heading">
                ThreatScope
              </h2>
              <p className="text-slate-400 text-sm mt-2 leading-relaxed">
                {t('dashboard.threatscope_desc')}
              </p>

              <div className="flex flex-wrap gap-2 mt-6">
                <span className="px-2.5 py-1 rounded-md bg-white/5 border border-white/10 text-slate-300 text-xs font-medium">
                  {t('dashboard.threatscope_tag1')}
                </span>
                <span className="px-2.5 py-1 rounded-md bg-white/5 border border-white/10 text-slate-300 text-xs font-medium">
                  {t('dashboard.threatscope_tag2')}
                </span>
                <span className="px-2.5 py-1 rounded-md bg-white/5 border border-white/10 text-slate-300 text-xs font-medium">
                  {t('dashboard.threatscope_tag3')}
                </span>
              </div>
            </div>

            <div className="mt-8 pt-6 border-t border-white/10 flex items-center justify-between text-accent text-sm font-bold group-hover:translate-x-[-4px] transition-transform">
              <span>{t('dashboard.threatscope_enter')}</span>
              <ArrowLeft className="w-5 h-5" />
            </div>
          </Link>

          {/* LogScope Card */}
          <Link
            href="/logscope"
            className="workspace-card glass-panel p-8 group relative overflow-hidden transition-all duration-300 hover:border-emerald-500/50 hover:shadow-2xl hover:shadow-emerald-500/10 flex flex-col justify-between"
          >
            <div className="absolute top-0 right-0 w-32 h-32 bg-emerald-500/10 rounded-full blur-2xl pointer-events-none group-hover:bg-emerald-500/20 transition-colors"></div>
            
            <div>
              <div className="flex items-center justify-between mb-6">
                <div className="w-14 h-14 rounded-2xl bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400 group-hover:scale-110 group-hover:shadow-lg group-hover:shadow-emerald-500/20 transition-all">
                  <Terminal className="w-7 h-7" />
                </div>
                <div className="flex items-center gap-2 px-3 py-1 rounded-full bg-dark-950/60 border border-white/10 text-xs">
                  <div className={`w-2 h-2 rounded-full ${services.logscope ? 'bg-emerald-400 animate-pulse' : 'bg-slate-500'}`}></div>
                  <span className="text-slate-300 font-medium">
                    {services.logscope ? t('dashboard.connected') : t('dashboard.ready')}
                  </span>
                </div>
              </div>

              <h2 className="text-2xl font-bold text-white group-hover:text-emerald-500 transition-colors flex items-center gap-2 font-heading">
                LogScope
              </h2>
              <p className="text-slate-400 text-sm mt-2 leading-relaxed">
                {t('dashboard.logscope_desc')}
              </p>

              <div className="flex flex-wrap gap-2 mt-6">
                <span className="px-2.5 py-1 rounded-md bg-white/5 border border-white/10 text-slate-300 text-xs font-medium">
                  {t('dashboard.logscope_tag1')}
                </span>
                <span className="px-2.5 py-1 rounded-md bg-white/5 border border-white/10 text-slate-300 text-xs font-medium">
                  {t('dashboard.logscope_tag2')}
                </span>
                <span className="px-2.5 py-1 rounded-md bg-white/5 border border-white/10 text-slate-300 text-xs font-medium">
                  {t('dashboard.logscope_tag3')}
                </span>
              </div>
            </div>

            <div className="mt-8 pt-6 border-t border-white/10 flex items-center justify-between text-emerald-500 text-sm font-bold group-hover:translate-x-[-4px] transition-transform">
              <span>{t('dashboard.logscope_enter')}</span>
              <ArrowLeft className="w-5 h-5" />
            </div>
          </Link>

        </div>
      </main>
    </div>
  );
}
