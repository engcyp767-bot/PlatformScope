import React from 'react';
import { Network, AlertTriangle, Globe, Server, ShieldAlert } from 'lucide-react';
import { PlatformConfig } from '../../../lib/types';
import { Field, SectionCard, inputClass } from './FormControls';

export function TabNetwork({
  config,
  onChange,
}: {
  config: PlatformConfig;
  onChange: (values: Partial<PlatformConfig['network']>) => void;
}) {
  const n = config.network;

  const ports = [n.frontend_port, n.gateway_port, n.analysis_port];
  const hasDuplicatePorts = new Set(ports).size !== ports.length;

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Prominent Restart Warning */}
      <div className="rounded-2xl border border-amber-500/30 bg-amber-500/10 p-5 flex items-start gap-4">
        <AlertTriangle className="w-6 h-6 text-amber-400 shrink-0 mt-0.5" />
        <div className="space-y-1.5 text-xs text-amber-100 leading-relaxed">
          <div className="font-black text-amber-300 text-sm">
            تنبيه حاسم: يتطلب إعادة تشغيل المنصة (Service Restart Required)
          </div>
          <p>
            تغيير منافذ الخدمات أو عنوان الاستماع لا يدخل حيز التنفيذ فورًا؛ يجب حفظ التغييرات ثم إعادة تشغيل
            المشغل الموحد (<code className="px-1.5 py-0.5 rounded bg-black/40 text-amber-200">python platform_launcher.py restart</code>)
            أو إعادة تشغيل الحاويات في حال التشغيل المجمع.
          </p>
        </div>
      </div>

      <SectionCard
        title="منافذ خدمات المنصة (Service Ports)"
        subtitle="تحديد منافذ TCP لكل مكوّن معماري؛ يجب أن تكون جميع المنافذ فريدة وغير مكررة"
      >
        {hasDuplicatePorts && (
          <div className="p-3 rounded-xl border border-rose-500/30 bg-rose-500/10 text-xs text-rose-300 font-bold mb-4">
            تحذير: توجد منافذ مكررة! يجب أن يملك كل مكوّن منفذ TCP مستقل.
          </div>
        )}

        <div className="grid md:grid-cols-3 gap-5">
          <Field
            label="منفذ الواجهة الأمامية (Frontend Port)"
            hint="المنفذ العام للواجهة Next.js المتاح للمحللين (الافتراضي: 3000)"
          >
            <input
              type="number"
              min={1}
              max={65535}
              className={inputClass}
              value={n.frontend_port}
              onChange={(e) => onChange({ frontend_port: Number(e.target.value) })}
            />
          </Field>

          <Field
            label="منفذ بوابة API (Gateway Port)"
            hint="المنفذ الخاص لبوابة Express المصادقة (الافتراضي: 8081)"
          >
            <input
              type="number"
              min={1}
              max={65535}
              className={inputClass}
              value={n.gateway_port}
              onChange={(e) => onChange({ gateway_port: Number(e.target.value) })}
            />
          </Field>

          <Field
            label="منفذ محرك التحليل الجنائي (Python Port)"
            hint="المنفذ الداخلي المعزول لمحرك Python والتقارير (الافتراضي: 8082)"
          >
            <input
              type="number"
              min={1}
              max={65535}
              className={inputClass}
              value={n.analysis_port}
              onChange={(e) => onChange({ analysis_port: Number(e.target.value) })}
            />
          </Field>
        </div>
      </SectionCard>

      <SectionCard
        title="عنوان الاستماع والوكيل الموثوق (Binding & Proxy)"
        subtitle="التحكم في عنوان ربط الشبكة والمهلة الزمنية لنقل الملفات الكبيرة"
      >
        <div className="grid md:grid-cols-2 gap-5">
          <Field
            label="عنوان استماع الواجهة (Bind Address)"
            hint="0.0.0.0 للاستماع على الشبكة الداخلية بأكملها أو 127.0.0.1 للمحلي فقط"
          >
            <input
              type="text"
              dir="ltr"
              className={inputClass}
              value={n.bind_address}
              onChange={(e) => onChange({ bind_address: e.target.value })}
              placeholder="0.0.0.0"
            />
          </Field>

          <Field
            label="مهلة الوكيل بالثواني (Proxy Timeout)"
            hint="المهلة الممنوحة لطلبات التحميل والمعالجة التوليدية الضخمة (10 - 1800 ثانية)"
          >
            <input
              type="number"
              min={10}
              max={1800}
              className={inputClass}
              value={n.proxy_timeout_seconds}
              onChange={(e) => onChange({ proxy_timeout_seconds: Number(e.target.value) })}
            />
          </Field>
        </div>

        <div className="pt-3 border-t border-white/5">
          <Field
            label="الأصول والواجهات الموثوقة (Trusted Origins / CORS)"
            hint="رابط في كل سطر مصرح له بإرسال استفسارات عبر البوابة (مثال: http://192.168.88.66:3000)"
          >
            <textarea
              rows={3}
              dir="ltr"
              className={inputClass}
              value={n.trusted_origins?.join('\n') || ''}
              onChange={(e) =>
                onChange({
                  trusted_origins: e.target.value.split(/\r?\n/).filter(Boolean),
                })
              }
              placeholder="http://192.168.88.66:3000"
            />
          </Field>
        </div>
      </SectionCard>
    </div>
  );
}
