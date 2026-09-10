import React from 'react';
import { ServerCog, ShieldAlert, Cpu, Database, Sliders } from 'lucide-react';
import { PlatformConfig } from '../../../lib/types';
import { Field, Toggle, SectionCard, inputClass } from './FormControls';

export function TabAnalysis({
  config,
  onChange,
}: {
  config: PlatformConfig;
  onChange: (values: Partial<PlatformConfig['analysis']>) => void;
}) {
  const a = config.analysis;

  return (
    <div className="space-y-6 animate-fade-in">
      <SectionCard
        title="آليات التحليل الذكي والتعلم التلقائي"
        subtitle="التحكم في فحص السمعة التلقائي ومحرك الذكاء والتعلم التراكمي من قرارات المحللين"
      >
        <div className="grid sm:grid-cols-3 gap-4">
          <Toggle
            checked={a.auto_enrich}
            onChange={(auto_enrich) => onChange({ auto_enrich })}
            label="فحص السمعة تلقائيًا (Auto Enrich)"
            description="فحص عناوين IP الخارجية تلقائيًا عند انتهاء قراءة الملف"
          />
          <Toggle
            checked={a.model_analysis_enabled}
            onChange={(model_analysis_enabled) => onChange({ model_analysis_enabled })}
            label="التحليل المساعد بالذكاء الاصطناعي"
            description="توليد خلاصات تفسيرية للأنماط الشاذة وسلاسل الهجوم"
          />
          <Toggle
            checked={a.learning_enabled}
            onChange={(learning_enabled) => onChange({ learning_enabled })}
            label="التعلم من تقييمات المحلل"
            description="تغذية قاعدة المعرفة المحلية بتصويبات وتأكيدات فريق SOC"
          />
        </div>
      </SectionCard>

      <SectionCard
        title="حدود درجات الخطورة والتصنيف الأمني (Risk Thresholds)"
        subtitle="المستويات الرقمية الفاصلة لتصنيف الحوادث والتهديدات في لوحات التحكم والتقارير"
      >
        <div className="space-y-5">
          <div className="grid md:grid-cols-3 gap-5">
            <Field
              label="عتبة الخطورة المتوسطة (Medium)"
              hint="الدرجة الأدنى لتصنيف الحدث كمتوسط (1 - 98)"
            >
              <input
                type="number"
                min={1}
                max={98}
                className={inputClass}
                value={a.medium_threshold}
                onChange={(e) => onChange({ medium_threshold: Number(e.target.value) })}
              />
            </Field>

            <Field
              label="عتبة الخطورة المرتفعة (High)"
              hint="الدرجة الفاصلة لتصنيف الحدث كمرتفع (أكبر من المتوسط)"
            >
              <input
                type="number"
                min={a.medium_threshold + 1}
                max={99}
                className={inputClass}
                value={a.high_threshold}
                onChange={(e) => onChange({ high_threshold: Number(e.target.value) })}
              />
            </Field>

            <Field
              label="عتبة الخطورة الحرجة (Critical)"
              hint="الدرجة الفاصلة للحوادث الحرجة P1 (أكبر من المرتفع)"
            >
              <input
                type="number"
                min={a.high_threshold + 1}
                max={100}
                className={inputClass}
                value={a.critical_threshold}
                onChange={(e) => onChange({ critical_threshold: Number(e.target.value) })}
              />
            </Field>
          </div>

          {/* Visual Scale Meter */}
          <div className="space-y-1.5 pt-2">
            <div className="flex justify-between text-xs font-bold text-slate-400">
              <span className="text-emerald-400">منخفض (Low: 0 - {a.medium_threshold - 1})</span>
              <span className="text-amber-400">متوسط (Medium: {a.medium_threshold} - {a.high_threshold - 1})</span>
              <span className="text-orange-400">مرتفع (High: {a.high_threshold} - {a.critical_threshold - 1})</span>
              <span className="text-rose-500">حرج (Critical: {a.critical_threshold} - 100)</span>
            </div>
            <div className="w-full h-3 rounded-full bg-slate-800 overflow-hidden flex border border-white/10">
              <div style={{ width: `${a.medium_threshold}%` }} className="bg-emerald-500/80" />
              <div style={{ width: `${a.high_threshold - a.medium_threshold}%` }} className="bg-amber-500/80" />
              <div style={{ width: `${a.critical_threshold - a.high_threshold}%` }} className="bg-orange-500/80" />
              <div style={{ width: `${100 - a.critical_threshold}%` }} className="bg-rose-600/90" />
            </div>
          </div>
        </div>
      </SectionCard>

      <SectionCard
        title="أداء المعالجة والتخزين المؤقت (Performance & Caching)"
        subtitle="ضبط التوازي وحصص الفحص الخارجي وصلاحية ذاكرة التخزين المؤقت في SQLite"
      >
        <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-5">
          <Field
            label="عدد عمال فحص IP المتوازي (Workers)"
            hint="خيوط المعالجة المتزامنة لاستعلام سمعة العناوين (1 - 32)"
          >
            <input
              type="number"
              min={1}
              max={32}
              className={inputClass}
              value={a.flow_workers}
              onChange={(e) => onChange({ flow_workers: Number(e.target.value) })}
            />
          </Field>

          <Field
            label="أقصى عناوين خارجية لـ FlowScope"
            hint="سقف العناوين الخارجية المفحوصة لكل ملف تدفقات (0 = بلا سقف)"
          >
            <input
              type="number"
              min={0}
              max={100000}
              className={inputClass}
              value={a.flow_max_external_ips}
              onChange={(e) => onChange({ flow_max_external_ips: Number(e.target.value) })}
            />
          </Field>

          <Field
            label="أقصى عناوين خارجية لـ LogScope"
            hint="سقف العناوين الخارجية المفحوصة لكل ملف سجلات (0 = بلا سقف)"
          >
            <input
              type="number"
              min={0}
              max={100000}
              className={inputClass}
              value={a.log_max_external_ips || 0}
              onChange={(e) => onChange({ log_max_external_ips: Number(e.target.value) })}
            />
          </Field>

          <Field
            label="صلاحية كاش FlowScope بالأيام"
            hint="مدة الاحتفاظ بنتائج السمعة السابقة قبل إعادة الفحص (0 = دائم)"
          >
            <input
              type="number"
              min={0}
              max={3650}
              className={inputClass}
              value={a.flow_cache_ttl_days}
              onChange={(e) => onChange({ flow_cache_ttl_days: Number(e.target.value) })}
            />
          </Field>

          <Field
            label="صلاحية كاش ThreatScope بالأيام"
            hint="مدة صلاحية بصمات التجزئة في SQLite (0 = دائم)"
          >
            <input
              type="number"
              min={0}
              max={3650}
              className={inputClass}
              value={a.threat_cache_ttl_days}
              onChange={(e) => onChange({ threat_cache_ttl_days: Number(e.target.value) })}
            />
          </Field>

          <Field
            label="صلاحية كاش LogScope بالأيام"
            hint="مدة صلاحية فحص سمعة سجلات SIEM (0 = دائم)"
          >
            <input
              type="number"
              min={0}
              max={3650}
              className={inputClass}
              value={a.log_cache_ttl_days || 0}
              onChange={(e) => onChange({ log_cache_ttl_days: Number(e.target.value) })}
            />
          </Field>
        </div>
      </SectionCard>
    </div>
  );
}
