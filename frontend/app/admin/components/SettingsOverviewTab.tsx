'use client';

import React from 'react';
import Link from 'next/link';
import { SlidersHorizontal, ArrowUpRight, Shield, Cpu, HardDrive, Network } from 'lucide-react';

export function SettingsOverviewTab() {
  return (
    <div className="space-y-6">
      <div className="glass-panel p-6 rounded-2xl border border-white/10 bg-gradient-to-r from-slate-900 via-dark-900 to-dark-900">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="flex items-start gap-4">
            <div className="w-12 h-12 rounded-2xl bg-white/10 border border-white/20 flex items-center justify-center text-slate-300 shrink-0">
              <SlidersHorizontal className="w-6 h-6" />
            </div>
            <div>
              <h2 className="text-base font-bold text-white flex items-center gap-2">
                <span>إعدادات النظام والتهيئة المركزية (Central Platform Configuration)</span>
                <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-white/10 text-slate-300 border border-white/20">
                  17 تبويباً
                </span>
              </h2>
              <p className="text-xs text-slate-400 mt-1 leading-relaxed">
                تحكم شامل في خيارات المنصة، مزودي الذكاء الاصطناعي، استخبارات التهديدات، سياسات رفع الملفات، ومزامنة التوقيت NTP.
              </p>
            </div>
          </div>

          <Link
            href="/settings"
            className="px-5 py-2.5 rounded-xl bg-purple-600 hover:bg-purple-500 text-white font-bold text-xs flex items-center gap-2 shadow-lg shadow-purple-600/20 transition-all self-start sm:self-auto"
          >
            <span>فتح مركز الإعدادات الكامل</span>
            <ArrowUpRight className="w-4 h-4" />
          </Link>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 text-xs">
        <div className="glass-panel p-5 rounded-2xl border border-white/10 space-y-2">
          <div className="flex items-center gap-2 text-purple-400 font-bold">
            <Shield className="w-4 h-4" />
            <span>الأمان والجلسات</span>
          </div>
          <p className="text-slate-400 text-[11px] leading-relaxed">
            ضبط مدة الجلسات وسياسات القفل التلقائي لحماية المنظومة من محاولات التخمين.
          </p>
        </div>

        <div className="glass-panel p-5 rounded-2xl border border-white/10 space-y-2">
          <div className="flex items-center gap-2 text-cyan-400 font-bold">
            <Cpu className="w-4 h-4" />
            <span>محركات التحليل و AI</span>
          </div>
          <p className="text-slate-400 text-[11px] leading-relaxed">
            إعداد Ollama المحلي ومزودي الذكاء الاصطناعي وعتبات احتساب درجات الخطورة.
          </p>
        </div>

        <div className="glass-panel p-5 rounded-2xl border border-white/10 space-y-2">
          <div className="flex items-center gap-2 text-amber-400 font-bold">
            <HardDrive className="w-4 h-4" />
            <span>التخزين والاحتفاظ</span>
          </div>
          <p className="text-slate-400 text-[11px] leading-relaxed">
            متابعة استهلاك مساحة القرص وسياسات الاحتفاظ بمهام التحليل والسجلات الجنائية.
          </p>
        </div>

        <div className="glass-panel p-5 rounded-2xl border border-white/10 space-y-2">
          <div className="flex items-center gap-2 text-emerald-400 font-bold">
            <Network className="w-4 h-4" />
            <span>الشبكة والتكاملات</span>
          </div>
          <p className="text-slate-400 text-[11px] leading-relaxed">
            مفاتيح VirusTotal و AbuseIPDB وإعدادات المنافذ ومزامنة الوقت NTP.
          </p>
        </div>
      </div>
    </div>
  );
}

