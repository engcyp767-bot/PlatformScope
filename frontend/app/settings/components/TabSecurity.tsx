import React from 'react';
import { ShieldCheck, AlertTriangle, Lock, Clock, ShieldAlert } from 'lucide-react';
import { PlatformConfig } from '../../../lib/types';
import { Field, Toggle, SectionCard, inputClass } from './FormControls';

export function TabSecurity({
  config,
  onChange,
}: {
  config: PlatformConfig;
  onChange: (values: Partial<PlatformConfig['security']>) => void;
}) {
  const s = config.security;

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Restart Warning Notice */}
      <div className="rounded-2xl border border-amber-500/30 bg-amber-500/10 p-4 sm:p-5 flex items-start gap-3.5">
        <AlertTriangle className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
        <div className="space-y-1 text-xs text-amber-100 leading-relaxed">
          <div className="font-black text-amber-300 text-sm">تنبيه أمني وإعادة تشغيل الخدمة</div>
          <p>
            تعديل سياسات الجلسات وملفات تعريف الارتباط (Cookies) يتطلب إعادة تشغيل بوابة API Gateway ومحرك التحليل
            لتسري التغييرات بالكامل، لأن تعديلها أثناء الاتصال النشط قد ينهي جلسات المحللين الحالية.
          </p>
        </div>
      </div>

      <SectionCard
        title="إدارة الجلسات والمصادقة (Sessions & Auth)"
        subtitle="تحديد مدة بقاء جلسة تسجيل الدخول وسياسة انتهاء الصلاحية التلقائية"
      >
        <div className="grid md:grid-cols-2 gap-5">
          <Field
            label="مدة بقاء الجلسة بالساعات (Session Hours)"
            hint="المدة الزمنية لصلاحية كوكي الجلسة قبل طلب تسجيل الدخول مجددًا (1 - 168 ساعة)"
          >
            <input
              type="number"
              min={1}
              max={168}
              className={inputClass}
              value={s.session_hours}
              onChange={(e) => onChange({ session_hours: Number(e.target.value) })}
            />
          </Field>

          <Field
            label="كوكي مشفر عبر HTTPS فقط (Secure Cookie)"
            hint="يمنع إرسال كوكي المصادقة عبر اتصالات HTTP غير المشفرة"
          >
            <div className="pt-1">
              <Toggle
                checked={s.secure_cookie}
                onChange={(secure_cookie) => onChange({ secure_cookie })}
                label="تفعيل اشتراط اتصال HTTPS الآمن"
                description="ملاحظة: لا تفعل هذا الخيار إلا إذا كانت المنصة تعمل خلف شهادة SSL/TLS وإلا سيتعذر الدخول"
              />
            </div>
          </Field>
        </div>
      </SectionCard>

      <SectionCard
        title="سياسة حماية تسجيل الدخول والتخمين (Rate Limiting & Lockout)"
        subtitle="حماية المنصة من محاولات التخمين وهجمات القوة الغاشمة (Brute-Force Protection)"
      >
        <div className="grid md:grid-cols-2 gap-5">
          <Field
            label="الحد الأقصى لمحاولات الدخول الفاشلة"
            hint="عدد المحاولات الفاشلة المسموح بها قبل حظر عنوان IP مؤقتًا (2 - 30 محاولة)"
          >
            <input
              type="number"
              min={2}
              max={30}
              className={inputClass}
              value={s.login_max_attempts}
              onChange={(e) => onChange({ login_max_attempts: Number(e.target.value) })}
            />
          </Field>

          <Field
            label="نافذة رصد وحظر المحاولات بالدقائق"
            hint="المدة الزمنية لحظر المحاولات وحساب سقف المحاولات الفاشلة (1 - 120 دقيقة)"
          >
            <input
              type="number"
              min={1}
              max={120}
              className={inputClass}
              value={s.login_window_minutes}
              onChange={(e) => onChange({ login_window_minutes: Number(e.target.value) })}
            />
          </Field>
        </div>
      </SectionCard>

      <SectionCard
        title="سياسات الأمان المؤسسية المعتمدة"
        subtitle="التدابير المطبقة تلقائيًا في نواة المنصة لحماية البيانات الجنائية"
      >
        <div className="grid sm:grid-cols-2 gap-3.5 text-xs">
          <div className="p-3.5 rounded-xl border border-white/5 bg-white/[0.015] space-y-1">
            <div className="font-bold text-white flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-emerald-400" />
              تشفير كلمات المرور
            </div>
            <p className="text-slate-400 text-[11px] leading-relaxed">
              تشفير PBKDF2-SHA256 مع 310,000 دورة تكرار وتمليح عشوائي مشفر لكل مستخدم.
            </p>
          </div>
          <div className="p-3.5 rounded-xl border border-white/5 bg-white/[0.015] space-y-1">
            <div className="font-bold text-white flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-emerald-400" />
              حماية ملفات الأدلة والجلسات
            </div>
            <p className="text-slate-400 text-[11px] leading-relaxed">
              عزل تخزين الأدلة الرقمية وخزنة الأدلة (Evidence Vault) مع التحقق من بصمة SHA-256.
            </p>
          </div>
        </div>
      </SectionCard>
    </div>
  );
}
