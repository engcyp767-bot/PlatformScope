import React, { useState } from 'react';
import {
  Sparkles, Plus, Trash2, TestTube2, Eye, EyeOff, Bot,
  AlertCircle, CheckCircle2, Sliders, ExternalLink
} from 'lucide-react';
import { PlatformConfig, AiProvider } from '../../../lib/types';
import { Field, Toggle, SectionCard, inputClass, selectClass } from './FormControls';
import { testPlatformConnection } from '../../../lib/api';
import { createClientId } from '../../../lib/client-id';

export function TabAI({
  config,
  onChange,
}: {
  config: PlatformConfig;
  onChange: (values: Partial<PlatformConfig>) => void;
}) {
  const [showSecrets, setShowSecrets] = useState(false);
  const [testStates, setTestStates] = useState<Record<string, { status: string; message: string }>>({});

  const providers = config.ai_providers || [];

  const addProvider = () => {
    const newProvider: AiProvider = {
      id: createClientId(),
      name: 'مزود AI جديد',
      enabled: true,
      base_url: 'https://api.openai.com',
      chat_path: '/v1/chat/completions',
      models_path: '/v1/models',
      model: 'gpt-4o-mini',
      auth_header: 'Authorization',
      auth_prefix: 'Bearer ',
      api_key: '',
      timeout_seconds: 180,
      priority: 10,
    };
    onChange({ ai_providers: [...providers, newProvider] });
  };

  const updateProvider = (index: number, partial: Partial<AiProvider>) => {
    const updated = [...providers];
    updated[index] = { ...updated[index], ...partial };
    onChange({ ai_providers: updated });
  };

  const removeProvider = (index: number) => {
    onChange({ ai_providers: providers.filter((_, i) => i !== index) });
  };

  const handleTest = async (provider: AiProvider) => {
    setTestStates((prev) => ({ ...prev, [provider.id]: { status: 'testing', message: 'جارٍ فحص الاتصال...' } }));
    try {
      const res = await testPlatformConnection({
        kind: 'ai',
        provider,
      });
      if (res.ok) {
        setTestStates((prev) => ({
          ...prev,
          [provider.id]: { status: 'success', message: res.message || 'تم الاتصال بالمزود بنجاح.' },
        }));
      } else {
        setTestStates((prev) => ({
          ...prev,
          [provider.id]: { status: 'error', message: res.message || 'فشل الاتصال بالمزود.' },
        }));
      }
    } catch (err: any) {
      setTestStates((prev) => ({
        ...prev,
        [provider.id]: { status: 'error', message: err.message || 'تعذر الاتصال بالمزود.' },
      }));
    }
  };

  return (
    <div className="space-y-6 animate-fade-in">
      <SectionCard
        title="مزودو الذكاء الاصطناعي المتوافقون مع OpenAI"
        subtitle="أضف مزودي LLM خارجيين أو داخليين متوافقين مع معيار OpenAI API. تُجرّب الخدمات حسب الأولوية تنازليًا."
        action={
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => setShowSecrets(!showSecrets)}
              className="px-3 py-2 rounded-xl border border-white/10 text-xs font-semibold text-slate-400 hover:text-white flex items-center gap-1.5 transition-colors"
            >
              {showSecrets ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
              {showSecrets ? 'إخفاء المفاتيح' : 'إظهار المفاتيح'}
            </button>
            <button
              type="button"
              onClick={addProvider}
              className="px-3.5 py-2 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 text-xs font-black flex items-center gap-1.5 transition-colors"
            >
              <Plus className="w-4 h-4" />
              إضافة مزود AI
            </button>
          </div>
        }
      >
        {providers.length === 0 ? (
          <div className="p-8 rounded-2xl border border-dashed border-white/10 text-center space-y-3 bg-white/[0.01]">
            <Bot className="w-10 h-10 text-slate-600 mx-auto" />
            <div className="font-bold text-sm text-slate-300">لم تتم إضافة أي مزود AI خارجي بعد</div>
            <p className="text-xs text-slate-500 max-w-md mx-auto leading-relaxed">
              يمكنك إضافة OpenAI أو Azure OpenAI أو vLLM أو LiteLLM أو أي خادم محلي يدعم واجهة OpenAI API.
              تستمر المنصة بالتحليل الجنائي المحلي والقواعد حتى لو لم يُضف أي مزود.
            </p>
          </div>
        ) : (
          <div className="space-y-5">
            {providers.map((p, index) => {
              const test = testStates[p.id];
              return (
                <div
                  key={p.id}
                  className="rounded-2xl border border-white/10 bg-white/[0.015] p-5 space-y-4 relative"
                >
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-white/5 pb-3">
                    <div className="flex items-center gap-3">
                      <Toggle
                        checked={p.enabled}
                        onChange={(enabled) => updateProvider(index, { enabled })}
                        label={p.name || 'مزود بدون اسم'}
                      />
                      <span className="px-2 py-0.5 rounded-full text-[10px] font-black bg-cyan-500/10 text-cyan-400 border border-cyan-500/25">
                        الأولوية: {p.priority}
                      </span>
                    </div>
                    <button
                      type="button"
                      onClick={() => removeProvider(index)}
                      className="p-1.5 rounded-lg text-slate-400 hover:text-rose-400 hover:bg-rose-500/10 transition-colors self-end sm:self-auto"
                      title="حذف المزود"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </div>

                  <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-4">
                    <Field label="اسم المزود التعريفي">
                      <input
                        type="text"
                        className={inputClass}
                        value={p.name}
                        onChange={(e) => updateProvider(index, { name: e.target.value })}
                        placeholder="OpenAI الإنتاجي"
                      />
                    </Field>

                    <Field label="الرابط الأساسي (Base URL)">
                      <input
                        type="text"
                        dir="ltr"
                        className={inputClass}
                        value={p.base_url}
                        onChange={(e) => updateProvider(index, { base_url: e.target.value })}
                        placeholder="https://api.openai.com"
                      />
                    </Field>

                    <Field label="اسم المودل (Model Identifier)">
                      <input
                        type="text"
                        dir="ltr"
                        className={inputClass}
                        value={p.model}
                        onChange={(e) => updateProvider(index, { model: e.target.value })}
                        placeholder="gpt-4o-mini"
                      />
                    </Field>

                    <Field label="الأولوية (Priority)" hint="الرقم الأقل يُجرّب أولًا (1 - 100)">
                      <input
                        type="number"
                        min={1}
                        max={100}
                        className={inputClass}
                        value={p.priority}
                        onChange={(e) => updateProvider(index, { priority: Number(e.target.value) })}
                      />
                    </Field>

                    <Field label="مفتاح API (Secret API Key)">
                      <input
                        type={showSecrets ? 'text' : 'password'}
                        dir="ltr"
                        className={inputClass}
                        value={p.api_key}
                        onChange={(e) => updateProvider(index, { api_key: e.target.value })}
                        placeholder="sk-••••••••••••"
                      />
                    </Field>

                    <Field label="مهلة الاستجابة بالثواني (Timeout)">
                      <input
                        type="number"
                        min={10}
                        max={600}
                        className={inputClass}
                        value={p.timeout_seconds}
                        onChange={(e) => updateProvider(index, { timeout_seconds: Number(e.target.value) })}
                      />
                    </Field>

                    <Field label="مسار المحادثة (Chat Path)">
                      <input
                        type="text"
                        dir="ltr"
                        className={inputClass}
                        value={p.chat_path}
                        onChange={(e) => updateProvider(index, { chat_path: e.target.value })}
                        placeholder="/v1/chat/completions"
                      />
                    </Field>

                    <Field label="مسار فحص المودلات (Models Path)">
                      <input
                        type="text"
                        dir="ltr"
                        className={inputClass}
                        value={p.models_path}
                        onChange={(e) => updateProvider(index, { models_path: e.target.value })}
                        placeholder="/v1/models"
                      />
                    </Field>

                    <Field label="بادئة الترويسة (Auth Prefix)">
                      <input
                        type="text"
                        dir="ltr"
                        className={inputClass}
                        value={p.auth_prefix}
                        onChange={(e) => updateProvider(index, { auth_prefix: e.target.value })}
                        placeholder="Bearer "
                      />
                    </Field>
                  </div>

                  {/* Actions & Test Status */}
                  <div className="flex flex-wrap items-center justify-between gap-3 pt-3 border-t border-white/5">
                    <button
                      type="button"
                      onClick={() => handleTest(p)}
                      disabled={test?.status === 'testing'}
                      className="px-3.5 py-2 rounded-xl border border-white/15 bg-white/5 hover:bg-white/10 text-xs font-bold text-slate-200 flex items-center gap-2 transition-colors disabled:opacity-50"
                    >
                      <TestTube2 className="w-3.5 h-3.5 text-cyan-400" />
                      {test?.status === 'testing' ? 'جارٍ الفحص...' : 'اختبار اتصال المزود'}
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
