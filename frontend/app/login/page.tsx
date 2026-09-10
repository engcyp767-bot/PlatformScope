'use client';

import React, { Suspense, useEffect, useState } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import { AlertCircle, ArrowLeft, Eye, EyeOff, Lock, ShieldCheck, User } from 'lucide-react';
import { fetchApi } from '../../lib/api';
import { useTranslation } from '../../lib/i18n';

function LoginForm() {
  const { t } = useTranslation();
  const router = useRouter();
  const searchParams = useSearchParams();
  const requestedNext = searchParams.get('next');
  const [defaultRoute, setDefaultRoute] = useState('/');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (requestedNext) return;
    fetchApi('/api/settings/public').then((payload) => {
      const app = payload?.general?.default_app;
      setDefaultRoute(app === 'flowscope' ? '/flowscope' : app === 'threatscope' ? '/threatscope' : app === 'logscope' ? '/logscope' : '/');
    }).catch(() => undefined);
  }, [requestedNext]);

  const handleSubmit = async (event: React.FormEvent) => {
    event.preventDefault();
    setError('');
    setLoading(true);
    try {
      const response = await fetchApi('/api/auth/login', {
        method: 'POST',
        body: JSON.stringify({ username, password }),
      });
      if (response.authenticated) router.push(requestedNext || defaultRoute);
    } catch (caught: unknown) {
      setError(caught instanceof Error ? caught.message : t('login.error'));
    } finally {
      setLoading(false);
    }
  };

  return (
    <form onSubmit={handleSubmit} className="login-form">
      {error && <div className="login-error" role="alert"><AlertCircle /><span>{error}</span></div>}
      <label className="login-field">
        <span>{t('login.username')}</span>
        <span className="login-input-wrap">
          <User aria-hidden="true" />
          <input type="text" required autoComplete="username" value={username} onChange={(event) => setUsername(event.target.value)} placeholder={t('login.username_placeholder')} autoFocus />
        </span>
      </label>
      <label className="login-field">
        <span>{t('login.password')}</span>
        <span className="login-input-wrap">
          <Lock aria-hidden="true" />
          <input type={showPassword ? 'text' : 'password'} required autoComplete="current-password" value={password} onChange={(event) => setPassword(event.target.value)} placeholder={t('login.password_placeholder')} />
          <button type="button" className="login-password-toggle" aria-label={showPassword ? t('login.hide_password') : t('login.show_password')} onClick={() => setShowPassword((value) => !value)}>
            {showPassword ? <EyeOff /> : <Eye />}
          </button>
        </span>
      </label>
      <div className="login-session-note flex justify-between px-2 w-full">
        <label className="flex items-center gap-2 cursor-pointer">
          <input type="checkbox" className="accent-cyan-400" />
          <span>{t('login.remember_me')}</span>
        </label>
        <a href="#" className="hover:text-cyan-400 transition-colors">{t('login.forgot_password')}</a>
      </div>
      <button type="submit" disabled={loading} className="login-submit">
        {loading ? <span className="login-spinner" /> : <><span>{t('login.login_btn')}</span><ArrowLeft /></>}
      </button>
    </form>
  );
}

function AnimatedLamp({ active, onToggle }: { active: boolean; onToggle: () => void }) {
  const { t } = useTranslation();
  return (
    <div className={`security-lamp ${active ? 'is-on' : ''}`}>
      <div className="lamp-aura" /><div className="lamp-beam" /><div className="lamp-head"><span /></div>
      <div className="lamp-neck" /><div className="lamp-stem" /><div className="lamp-base" />
      <button type="button" className="lamp-pull" onClick={onToggle} aria-label={active ? t('login.turn_off_lamp') : t('login.turn_on_lamp')}><span /></button>
      <div className="lamp-floor-glow" />
    </div>
  );
}

function LoginExperience() {
  const [lampEnabled, setLampEnabled] = useState(false);
  const { t } = useTranslation();
  const [brandTitle, setBrandTitle] = useState('بوابة التحليل الأمني');
  
  useEffect(() => {
    fetchApi('/api/settings/public').then((res) => {
      if (res.appearance?.platform_title) setBrandTitle(res.appearance.platform_title);
    }).catch(() => {});
  }, []);

  return (
    <main className={`login-stage ${lampEnabled ? 'lamp-active' : 'lamp-off'}`}>
      <div className="login-grid" /><div className="login-scan" />
      <div className="login-brand-mini">
        <ShieldCheck />
        <div><strong>{brandTitle}</strong><span>SECURITY ANALYSIS CENTER</span></div>
      </div>
      <section className="login-scene" aria-label={t('login.title')}>
        <div className="login-lamp-side">
          <AnimatedLamp active={lampEnabled} onToggle={() => setLampEnabled((value) => !value)} />
          <p>{lampEnabled ? t('login.lamp_on_hint') : t('login.lamp_off_hint')}</p>
        </div>
        <div className="login-panel-wrap" aria-hidden={!lampEnabled}>
          <span className="login-panel-glow" />
          <span className="login-panel-orbit" />
          <div className="login-core">
            <header className="login-heading">
              <h1>{t('login.title')}</h1>
              <p>{t('login.subtitle')}</p>
            </header>
            <Suspense fallback={<div className="login-loading">{t('login.loading')}</div>}><LoginForm /></Suspense>
            <footer className="login-footer border-t-0 mt-4 pt-0">
              {t('login.no_account')} <a href="#" className="text-cyan-400 font-bold hover:underline">{t('login.create_account')}</a>
            </footer>
          </div>
        </div>
      </section>
    </main>
  );
}

export default function LoginPage() { return <LoginExperience />; }
