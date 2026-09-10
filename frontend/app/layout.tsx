import './globals.css';
import type { Metadata } from 'next';
import { PlatformAtmosphere, ThemeSettings } from '../components/ThemeSettings';
import { I18nProvider } from '../lib/i18n';

export const metadata: Metadata = {
  title: 'بوابة التحليل الأمني | Security Analysis Center',
  description: 'منصة موحدة لتحليل تدفقات الشبكة FlowScope وسجلات الأمان LogScope وتنبيهات XDR ThreatScope',
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="ar" dir="rtl" data-theme="dark" data-animations="true" suppressHydrationWarning>
      <head>
        <link rel="icon" href="/favicon.png" type="image/png" />
      </head>
      <body className="platform-shell antialiased selection:bg-primary/30 selection:text-white">
        <script dangerouslySetInnerHTML={{ __html: `try{const a=JSON.parse(localStorage.getItem('platform-appearance')||'{}');const r=document.documentElement;r.dataset.theme=a.theme||'dark';r.dataset.compact=a.compact_mode?'true':'false';r.dataset.animations=a.animations===false?'false':'true';const q=new URLSearchParams(window.location.search).get('sidebar');if(q==='closed'||q==='0'){document.body.classList.remove('sidebar-expanded')}else if(q==='open'||q==='1'){document.body.classList.add('sidebar-expanded')}else{const s=localStorage.getItem('platform-sidebar-open');if(s==='true'||(s===null&&window.innerWidth>=1280)){document.body.classList.add('sidebar-expanded')}else{document.body.classList.remove('sidebar-expanded')}}}catch(e){}` }} />
        <ThemeSettings />
        <PlatformAtmosphere />
        <I18nProvider>
          {children}
        </I18nProvider>
      </body>
    </html>
  );
}
