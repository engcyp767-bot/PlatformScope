import React, { useState } from 'react';
import { Bot, TestTube2, RefreshCw, CheckCircle2, AlertCircle, Sparkles } from 'lucide-react';
import { PlatformConfig } from '../../../lib/types';
import { Field, Toggle, SectionCard, inputClass } from './FormControls';
import { testPlatformConnection } from '../../../lib/api';

export function TabOllama({
  config,
  onChange,
}: {
  config: PlatformConfig;
  onChange: (values: Partial<PlatformConfig['ollama']>) => void;
}) {
  const o = config.ollama;
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<{ ok: boolean; message: string; sample?: string } | null>(null);

  const handleTest = async () => {
    setTesting(true);
    setTestResult(null);
    try {
      const res = await testPlatformConnection({
        kind: 'ollama',
        url: o.url,
      });
      setTestResult(res);
    } catch (err: any) {
      setTestResult({ ok: false, message: err.message || 'فشل الاتصال بخادم Ollama.' });
    }
    setTesting(false);
  };

  return (
    <div className="space-y-6 animate-fade-in">
      <SectionCard
        title="خادم Ollama والذكاء الاصطناعي المحلي"
        subtitle="التحليل المساعد غير المتصل بالإنترنت (On-Premises LLM) لتفسير التهديدات دون إرسال البيانات خارج الشبكة"
      >
        <div className="space-y-5">
          <Toggle
            checked={o.enabled}
            onChange={(enabled) => onChange({ enabled })}
            label="تفعيل الاستعانة بخادم Ollama المحلي"
            description="عند تفعيله، يستعين محرك التحليل بـ Ollama بعد تجربة مزودي AI الخارجيين لتوليد تحليلات التهديدات وتلخيصها"
          />

          <div className="grid md:grid-cols-2 gap-5 pt-2">
            <Field
              label="عنوان ورابط خادم Ollama (Endpoint URL)"
              hint="عنوان الاستماع الافتراضي لخادم Ollama (مثال: http://127.0.0.1:11434)"
            >
              <input
                type="text"
                dir="ltr"
                disabled={!o.enabled}
                className={inputClass}
                value={o.url}
                onChange={(e) => onChange({ url: e.target.value })}
                placeholder="http://127.0.0.1:11434"
              />
            </Field>

            <Field
              label="النموذج الرئيسي المفضل (Preferred Model)"
              hint="اسم النموذج المستهدف في Ollama (مثال: gemma4:31b أو llama3.1)"
            >
              <input
                type="text"
                dir="ltr"
                disabled={!o.enabled}
                className={inputClass}
                value={o.preferred_model}
                onChange={(e) => onChange({ preferred_model: e.target.value })}
                placeholder="gemma4:31b"
              />
            </Field>

            <Field
              label="النموذج الاحتياطي (Fallback Model)"
              hint="النموذج البديل عند تعذر النموذج الرئيسي أو انشغاله"
            >
              <input
                type="text"
                dir="ltr"
                disabled={!o.enabled}
                className={inputClass}
                value={o.fallback_model}
                onChange={(e) => onChange({ fallback_model: e.target.value })}
                placeholder="gpt-oss:20b"
              />
            </Field>

            <Field
              label="مهلة الاستجابة بالثواني (Timeout)"
              hint="المهلة الممنوحة للاستدلال قبل التراجع للقواعد المحلية (10 - 600 ثانية)"
            >
              <input
                type="number"
                min={10}
                max={600}
                disabled={!o.enabled}
                className={inputClass}
                value={o.timeout_seconds}
                onChange={(e) => onChange({ timeout_seconds: Number(e.target.value) })}
              />
            </Field>

            <Field
              label="الحد الأقصى لسجلات السياق (Max Threat Records)"
              hint="عدد السجلات المشبوهة المرفقة في سياق الاستفسار (5 - 60 سجلًا)"
            >
              <input
                type="number"
                min={5}
                max={60}
                disabled={!o.enabled}
                className={inputClass}
                value={o.max_records}
                onChange={(e) => onChange({ max_records: Number(e.target.value) })}
              />
            </Field>
          </div>

          <div className="flex flex-wrap items-center justify-between gap-3 pt-4 border-t border-white/5">
            <button
              type="button"
              onClick={handleTest}
              disabled={!o.enabled || testing}
              className="px-4 py-2 rounded-xl border border-cyan-500/30 bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-300 text-xs font-bold flex items-center gap-2 transition-colors disabled:opacity-40"
            >
              <TestTube2 className={`w-4 h-4 ${testing ? 'animate-spin' : ''}`} />
              {testing ? 'جارٍ اختبار الاتصال بـ Ollama...' : 'اختبار اتصال Ollama وجلب النماذج'}
            </button>

            {testResult && (
              <div className="text-xs flex items-center gap-2">
                {testResult.ok ? (
                  <span className="text-emerald-400 font-bold flex items-center gap-1.5">
                    <CheckCircle2 className="w-4 h-4" /> {testResult.message}
                  </span>
                ) : (
                  <span className="text-rose-400 font-bold flex items-center gap-1.5">
                    <AlertCircle className="w-4 h-4" /> {testResult.message}
                  </span>
                )}
              </div>
            )}
          </div>

          {testResult?.sample && (
            <div className="p-3 rounded-xl border border-white/10 bg-dark-950/60 space-y-1 text-xs">
              <span className="text-slate-400 text-[11px] block">استجابة نقطة /api/tags:</span>
              <pre className="text-slate-300 font-mono text-[10px] overflow-x-auto p-2 bg-black/30 rounded-lg">
                {testResult.sample}
              </pre>
            </div>
          )}
        </div>
      </SectionCard>
    </div>
  );
}
