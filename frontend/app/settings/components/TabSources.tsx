import React from 'react';
import { Database, Plus, Trash2, Layers } from 'lucide-react';
import { PlatformConfig } from '../../../lib/types';
import { Field, SectionCard, inputClass } from './FormControls';

export function TabSources({
  config,
  onChange,
}: {
  config: PlatformConfig;
  onChange: (values: Partial<PlatformConfig>) => void;
}) {
  const sources = config.source_systems;

  const updateSource = (
    app: 'flowscope' | 'threatscope' | 'logscope',
    index: number,
    field: 'label' | 'description',
    val: string
  ) => {
    const list = [...(sources[app] || [])];
    list[index] = { ...list[index], [field]: val };
    onChange({ source_systems: { ...sources, [app]: list } });
  };

  const addSource = (app: 'flowscope' | 'threatscope' | 'logscope') => {
    const list = [...(sources[app] || [])];
    const id = `${app.slice(0, 4)}_${list.length + 1}`;
    list.push({ id, label: `بيئة جديدة ${list.length + 1}`, description: 'وصف البيئة أو المركز' });
    onChange({ source_systems: { ...sources, [app]: list } });
  };

  const removeSource = (app: 'flowscope' | 'threatscope' | 'logscope', index: number) => {
    const list = [...(sources[app] || [])].filter((_, i) => i !== index);
    onChange({ source_systems: { ...sources, [app]: list } });
  };

  const apps: Array<{ id: 'flowscope' | 'threatscope' | 'logscope'; title: string; subtitle: string }> = [
    {
      id: 'flowscope',
      title: 'بيئات FlowScope (تدفقات الشبكة)',
      subtitle: 'مسميات مراكز تدفقات Flowmon و ADS (الدخول، مركز البيانات، الخروج)',
    },
    {
      id: 'threatscope',
      title: 'بيئات ThreatScope (سجلات وبصمات XDR)',
      subtitle: 'بيئات رصد التهديدات والأجهزة الطرفية وخوادم الإنتاج',
    },
    {
      id: 'logscope',
      title: 'بيئات ومستقبلات LogScope (أنظمة SIEM)',
      subtitle: 'أنظمة إدارة السجلات المركزية مثل ManageEngine Log360 و Splunk و Syslog',
    },
  ];

  return (
    <div className="space-y-6 animate-fade-in">
      {apps.map((app) => (
        <SectionCard
          key={app.id}
          title={app.title}
          subtitle={app.subtitle}
          action={
            <button
              type="button"
              onClick={() => addSource(app.id)}
              className="px-3 py-1.5 rounded-xl border border-white/10 bg-white/5 hover:bg-white/10 text-xs font-bold text-cyan-300 flex items-center gap-1.5 transition-colors"
            >
              <Plus className="w-3.5 h-3.5" />
              إضافة بيئة
            </button>
          }
        >
          <div className="space-y-3">
            {(sources[app.id] || []).map((s, idx) => (
              <div
                key={s.id || idx}
                className="grid sm:grid-cols-[140px_1fr_40px] items-center gap-3 p-3 rounded-xl border border-white/5 bg-white/[0.015]"
              >
                <div>
                  <label className="block text-[10px] text-slate-500 font-bold mb-1">الاسم المختصر</label>
                  <input
                    type="text"
                    dir="ltr"
                    className={inputClass}
                    value={s.label}
                    onChange={(e) => updateSource(app.id, idx, 'label', e.target.value)}
                  />
                </div>
                <div>
                  <label className="block text-[10px] text-slate-500 font-bold mb-1">الوصف التفصيلي</label>
                  <input
                    type="text"
                    className={inputClass}
                    value={s.description}
                    onChange={(e) => updateSource(app.id, idx, 'description', e.target.value)}
                  />
                </div>
                <div className="pt-4 flex justify-center">
                  <button
                    type="button"
                    onClick={() => removeSource(app.id, idx)}
                    className="p-2 rounded-lg text-slate-500 hover:text-rose-400 hover:bg-rose-500/10 transition-colors"
                    title="حذف البيئة"
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>
                </div>
              </div>
            ))}
          </div>
        </SectionCard>
      ))}
    </div>
  );
}
