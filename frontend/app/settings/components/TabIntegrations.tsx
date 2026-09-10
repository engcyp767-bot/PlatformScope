import React, { useState } from 'react';
import {
  Key, Eye, EyeOff, Plus, Trash2, TestTube2, ShieldCheck,
  AlertCircle, CheckCircle2, Globe, Database
} from 'lucide-react';
import { PlatformConfig, ExternalApi } from '../../../lib/types';
import { Field, Toggle, SectionCard, inputClass, selectClass } from './FormControls';
import { testPlatformConnection } from '../../../lib/api';
import { createClientId } from '../../../lib/client-id';

export function TabIntegrations({
  config,
  onChange,
}: {
  config: PlatformConfig;
  onChange: (values: Partial<PlatformConfig>) => void;
}) {
  const [showSecrets, setShowSecrets] = useState(false);
  const [testStates, setTestStates] = useState<Record<string, { status: string; message: string }>>({});

  const p = config.providers;
  const external = config.external_apis || [];

  const updateProvider = (name: keyof PlatformConfig['providers'], partial: object) => {
    onChange({
      providers: {
        ...p,
        [name]: { ...p[name], ...partial },
      },
    });
  };

  const addExternal = () => {
    const item: ExternalApi = {
      id: createClientId(),
      name: 'API تهديدات مخصص',
      enabled: true,
      scope: 'both',
      base_url: 'https://api.threatintel.local',
      health_path: '/health',
      lookup_path: '/lookup/{indicator}',
      verdict_path: 'verdict',
      malicious_values: 'malicious,suspicious,high',
      auth_header: 'Authorization',
      api_key: '',
      timeout_seconds: 15,
    };
    onChange({ external_apis: [...external, item] });
  };

  const updateExternal = (index: number, partial: Partial<ExternalApi>) => {
    const list = [...external];
    list[index] = { ...list[index], ...partial };
    onChange({ external_apis: list });
  };

  const removeExternal = (index: number) => {
    onChange({ external_apis: external.filter((_, i) => i !== index) });
  };

  const testExternalApi = async (api: ExternalApi) => {
    setTestStates((prev) => ({ ...prev, [api.id]: { status: 'testing', message: 'جارٍ الفحص...' } }));
    try {
      const res = await testPlatformConnection({
        kind: 'external',
        provider: api,
      });
      if (res.ok) {
        setTestStates((prev) => ({
          ...prev,
          [api.id]: { status: 'success', message: res.message || 'تم الاتصال بالـ API بنجاح.' },
        }));
      } else {
        setTestStates((prev) => ({
          ...prev,
          [api.id]: { status: 'error', message: res.message || 'فشل الاتصال بالخدمة.' },
        }));
      }
    } catch (err: any) {
      setTestStates((prev) => ({
        ...prev,
        [api.id]: { status: 'error', message: err.message || 'تعذر الاتصال.' },
      }));
    }
  };

  return (
    <div className="space-y-6 animate-fade-in">
      <SectionCard
        title="مزودو فحص السمعة المدمجون (Reputation Providers)"
        subtitle="خدمات فحص سمعة العناوين والبصمات الرقمية المدمجة في محرك التحليل"
        action={
          <button
            type="button"
            onClick={() => setShowSecrets(!showSecrets)}
            className="px-3 py-2 rounded-xl border border-white/10 text-xs font-semibold text-slate-400 hover:text-white flex items-center gap-1.5 transition-colors"
          >
            {showSecrets ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
            {showSecrets ? 'إخفاء المفاتيح' : 'إظهار المفاتيح'}
          </button>
        }
      >
        <div className="grid lg:grid-cols-2 gap-5">
          {/* VirusTotal */}
          <div className="rounded-2xl border border-white/10 bg-white/[0.015] p-5 space-y-4">
            <Toggle
              checked={p.virustotal.enabled}
              onChange={(enabled) => updateProvider('virustotal', { enabled })}
              label="VirusTotal"
              description="فحص سمعة العناوين والبصمات الرقمية ودعم حوض المفاتيح المتعددة"
            />
            <Field
              label="حوض مفاتيح API (Key Pool)"
              hint="مفتاح في كل سطر؛ عند استنفاد حصة المفتاح الأول ينتقل المحرك تلقائيًا للمفتاح التالي"
            >
              <textarea
                rows={3}
                dir="ltr"
                disabled={!p.virustotal.enabled}
                className={inputClass}
                value={p.virustotal.api_keys.join('\n')}
                onChange={(e) =>
                  updateProvider('virustotal', {
                    api_keys: e.target.value.split(/\r?\n/).filter(Boolean),
                  })
                }
                placeholder="مفتاح API في كل سطر"
              />
            </Field>
          </div>

          {/* AbuseIPDB */}
          <div className="rounded-2xl border border-white/10 bg-white/[0.015] p-5 space-y-4">
            <Toggle
              checked={p.abuseipdb.enabled}
              onChange={(enabled) => updateProvider('abuseipdb', { enabled })}
              label="AbuseIPDB"
              description="فحص سمعة عناوين IP ونسبة الثقة في البلاغات الخبيثة"
            />
            <Field label="مفتاح API Key">
              <input
                type={showSecrets ? 'text' : 'password'}
                dir="ltr"
                disabled={!p.abuseipdb.enabled}
                className={inputClass}
                value={p.abuseipdb.api_key}
                onChange={(e) => updateProvider('abuseipdb', { api_key: e.target.value })}
                placeholder="••••••••••••"
              />
            </Field>
          </div>

          {/* MalwareBazaar */}
          <div className="rounded-2xl border border-white/10 bg-white/[0.015] p-5 space-y-4">
            <Toggle
              checked={p.malwarebazaar.enabled}
              onChange={(enabled) => updateProvider('malwarebazaar', { enabled })}
              label="MalwareBazaar"
              description="فحص بصمات عينات البرمجيات الخبيثة وتصنيفاتها"
            />
            <Field label="مفتاح Auth Key">
              <input
                type={showSecrets ? 'text' : 'password'}
                dir="ltr"
                disabled={!p.malwarebazaar.enabled}
                className={inputClass}
                value={p.malwarebazaar.api_key}
                onChange={(e) => updateProvider('malwarebazaar', { api_key: e.target.value })}
                placeholder="••••••••••••"
              />
            </Field>
          </div>

          {/* Shodan */}
          <div className="rounded-2xl border border-white/10 bg-white/[0.015] p-5 space-y-4">
            <Toggle
              checked={p.shodan.enabled}
              onChange={(enabled) => updateProvider('shodan', { enabled })}
              label="Shodan InternetDB"
              description="الاستعلام المجاني السريع عن المنافذ المفتوحة والثغرات المعروفة"
            />
            <div className="p-3.5 rounded-xl border border-emerald-500/20 bg-emerald-500/5 text-xs text-emerald-300">
              خدمة مجانية جاهزة ولا تتطلب مفتاح API إضافي، تعمل تلقائيًا عند تفعيلها.
            </div>
          </div>
        </div>
      </SectionCard>

      {/* Custom External APIs */}
      <SectionCard
        title="واجهات استخبارات التهديدات الإضافية (Custom Threat APIs)"
        subtitle="ربط المنصة بأي مصدر محلي أو خارجي عبر استعلامات REST JSON المهيكلة"
        action={
          <button
            type="button"
            onClick={addExternal}
            className="px-3.5 py-2 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 text-xs font-black flex items-center gap-1.5 transition-colors"
          >
            <Plus className="w-4 h-4" />
            إضافة API مخصص
          </button>
        }
      >
        {external.length === 0 ? (
          <div className="p-8 rounded-2xl border border-dashed border-white/10 text-center space-y-2 bg-white/[0.01]">
            <Globe className="w-8 h-8 text-slate-600 mx-auto" />
            <div className="font-bold text-xs text-slate-400">لم تتم إضافة أي واجهات مخصصة بعد</div>
            <p className="text-[11px] text-slate-500 max-w-sm mx-auto">
              يمكنك ربط منصة TIP داخلية أو خدمة فحص خاصة عبر مسار استعلام JSON.
            </p>
          </div>
        ) : (
          <div className="space-y-4">
            {external.map((item, idx) => {
              const test = testStates[item.id];
              return (
                <div
                  key={item.id}
                  className="rounded-2xl border border-white/10 bg-white/[0.015] p-5 space-y-4"
                >
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-white/5 pb-3">
                    <Toggle
                      checked={item.enabled}
                      onChange={(enabled) => updateExternal(idx, { enabled })}
                      label={item.name || 'API بدون اسم'}
                    />
                    <button
                      type="button"
                      onClick={() => removeExternal(idx)}
                      className="p-1.5 rounded-lg text-slate-400 hover:text-rose-400 hover:bg-rose-500/10 transition-colors self-end sm:self-auto"
                      title="حذف المصدر"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </div>

                  <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-4">
                    <Field label="اسم الخدمة">
                      <input
                        type="text"
                        className={inputClass}
                        value={item.name}
                        onChange={(e) => updateExternal(idx, { name: e.target.value })}
                      />
                    </Field>

                    <Field label="النطاق المستهدف (Scope)">
                      <select
                        className={selectClass}
                        value={item.scope}
                        onChange={(e) => updateExternal(idx, { scope: e.target.value as any })}
                      >
                        <option value="all">جميع المحركات (All)</option>
                        <option value="both">FlowScope و ThreatScope</option>
                        <option value="flowscope">FlowScope فقط</option>
                        <option value="threatscope">ThreatScope فقط</option>
                        <option value="logscope">LogScope فقط</option>
                      </select>
                    </Field>

                    <Field label="الرابط الأساسي (Base URL)">
                      <input
                        type="text"
                        dir="ltr"
                        className={inputClass}
                        value={item.base_url}
                        onChange={(e) => updateExternal(idx, { base_url: e.target.value })}
                        placeholder="https://tip.local"
                      />
                    </Field>

                    <Field label="مسار فحص الصحة (Health Path)">
                      <input
                        type="text"
                        dir="ltr"
                        className={inputClass}
                        value={item.health_path}
                        onChange={(e) => updateExternal(idx, { health_path: e.target.value })}
                        placeholder="/health"
                      />
                    </Field>

                    <Field label="مسار الاستعلام (Lookup Path)">
                      <input
                        type="text"
                        dir="ltr"
                        className={inputClass}
                        value={item.lookup_path}
                        onChange={(e) => updateExternal(idx, { lookup_path: e.target.value })}
                        placeholder="/lookup/{indicator}"
                      />
                    </Field>

                    <Field label="مسار الحكم داخل JSON">
                      <input
                        type="text"
                        dir="ltr"
                        className={inputClass}
                        value={item.verdict_path}
                        onChange={(e) => updateExternal(idx, { verdict_path: e.target.value })}
                        placeholder="data.verdict"
                      />
                    </Field>

                    <Field label="القيم المصنفة كتهديد">
                      <input
                        type="text"
                        dir="ltr"
                        className={inputClass}
                        value={item.malicious_values}
                        onChange={(e) => updateExternal(idx, { malicious_values: e.target.value })}
                        placeholder="malicious,suspicious,high"
                      />
                    </Field>

                    <Field label="ترويسة المصادقة (Auth Header)">
                      <input
                        type="text"
                        dir="ltr"
                        className={inputClass}
                        value={item.auth_header}
                        onChange={(e) => updateExternal(idx, { auth_header: e.target.value })}
                        placeholder="Authorization"
                      />
                    </Field>

                    <Field label="مفتاح API">
                      <input
                        type={showSecrets ? 'text' : 'password'}
                        dir="ltr"
                        className={inputClass}
                        value={item.api_key}
                        onChange={(e) => updateExternal(idx, { api_key: e.target.value })}
                        placeholder="••••••••••••"
                      />
                    </Field>
                  </div>

                  <div className="flex flex-wrap items-center justify-between gap-3 pt-3 border-t border-white/5">
                    <button
                      type="button"
                      onClick={() => testExternalApi(item)}
                      disabled={test?.status === 'testing'}
                      className="px-3.5 py-2 rounded-xl border border-white/15 bg-white/5 hover:bg-white/10 text-xs font-bold text-slate-200 flex items-center gap-2 transition-colors disabled:opacity-50"
                    >
                      <TestTube2 className="w-3.5 h-3.5 text-cyan-400" />
                      {test?.status === 'testing' ? 'جارٍ الفحص...' : 'اختبار الاتصال بالـ API'}
                    </button>

                    {test && (
                      <div className="text-xs flex items-center gap-1.5">
                        {test.status === 'success' && (
                          <span className="text-emerald-400 font-bold flex items-center gap-1">
                            <CheckCircle2 className="w-4 h-4" /> {test.message}
                          </span>
                        )}
                        {test.status === 'error' && (
                          <span className="text-rose-400 font-bold flex items-center gap-1">
                            <AlertCircle className="w-4 h-4" /> {test.message}
                          </span>
                        )}
                      </div>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </SectionCard>
    </div>
  );
}
