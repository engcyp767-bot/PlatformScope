import React from 'react';
import { Moon, Sun, Sparkles, Layers3, ServerCog, Palette, Eye } from 'lucide-react';
import { PlatformConfig } from '../../../lib/types';
import { Field, Toggle, SectionCard, inputClass } from './FormControls';

export function TabAppearance({
  config,
  onChange,
  onPreview,
}: {
  config: PlatformConfig;
  onChange: (values: Partial<PlatformConfig['appearance']>) => void;
  onPreview: (values: Partial<PlatformConfig['appearance']>) => void;
}) {
  const app = config.appearance;

  const themes = [
    {
      id: 'dark',
      title: 'الداكن الافتراضي (Dark)',
      desc: 'النمط المعتمد لمراكز العمليات الأمنية (SOC) مع خلفية كحلية داكنة.',
      icon: Moon,
      colors: ['#050912', '#00e5ff'],
    },
    {
      id: 'light',
      title: 'الفاتح المكتبي (Light)',
      desc: 'تباين بصري عالي مناسب لبيئات العمل المكتبية والإضاءة الساطعة.',
      icon: Sun,
      colors: ['#eef4fb', '#1677ff'],
    },
    {
      id: 'midnight',
      title: 'منتصف الليل (Midnight)',
      desc: 'سواد فاحم مريح للعين أثناء جلسات التحقيق والتحليل الطويلة.',
      icon: Sparkles,
      colors: ['#070a0f', '#00e5ff'],
    },
    {
      id: 'graphite',
      title: 'الجرافيت الرمادي (Graphite)',
      desc: 'درجات رمادية محايدة مع لمسات زمردية لتقليل الإجهاد البصري.',
      icon: Layers3,
      colors: ['#0b0d10', '#a7f3d0'],
    },
    {
      id: 'navy',
      title: 'الأزرق البحري (Navy)',
      desc: 'نمط بحري ملكي احترافي يبرز البيانات والمخططات البيانية.',
      icon: ServerCog,
      colors: ['#06101f', '#38bdf8'],
    },
  ];

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Theme Picker */}
      <SectionCard
        title="سمات المظهر (Themes)"
        subtitle="اختر السمة البصرية المناسبة لبيئة عملك من بين 5 سمات مصممة ومختبرة للمنصة"
      >
        <div className="grid sm:grid-cols-2 xl:grid-cols-3 gap-3.5">
          {themes.map((t) => {
            const isSelected = app.theme === t.id;
            const ThemeIcon = t.icon;

            return (
              <button
                key={t.id}
                type="button"
                onClick={() => {
                  onChange({ theme: t.id });
                  onPreview({ theme: t.id });
                }}
                className={`text-right p-4 rounded-2xl border transition-all relative overflow-hidden group ${
                  isSelected
                    ? 'border-cyan-400/80 bg-cyan-500/10 shadow-lg shadow-cyan-500/10'
                    : 'border-white/10 bg-white/[0.02] hover:bg-white/[0.05] hover:border-white/20'
                }`}
              >
                <div className="flex items-start justify-between gap-2 mb-3">
                  <div className="flex items-center gap-2">
                    <ThemeIcon className={`w-4 h-4 ${isSelected ? 'text-cyan-400' : 'text-slate-400'}`} />
                    <span className="font-bold text-xs text-white">{t.title}</span>
                  </div>
                  <div className="flex -space-x-1.5 space-x-reverse">
                    {t.colors.map((c, i) => (
                      <span
                        key={i}
                        className="w-4 h-4 rounded-full border border-white/20 shrink-0"
                        style={{ background: c }}
                      />
                    ))}
                  </div>
                </div>
                <p className="text-[11px] text-slate-400 leading-relaxed">{t.desc}</p>
              </button>
            );
          })}
        </div>
      </SectionCard>

      {/* Colors & Customization */}
      <SectionCard
        title="الألوان المخصصة وهوية المنصة"
        subtitle="تعديل اللون الأساسي ولون التمييز وعناوين المنصة الرسمية"
      >
        <div className="grid md:grid-cols-2 gap-5">
          <Field
            label="عنوان المنصة الرئيسي"
            hint="يظهر في شريط التنقل العلوي وتبويب المتصفح والتقارير الرسمية"
          >
            <input
              type="text"
              className={inputClass}
              value={app.platform_title}
              onChange={(e) => {
                onChange({ platform_title: e.target.value });
                onPreview({ platform_title: e.target.value });
              }}
            />
          </Field>

          <Field
            label="العنوان الفرعي للمنصة"
            hint="الشعار الفرعي الظاهر في صفحة تسجيل الدخول وملخص التقارير"
          >
            <input
              type="text"
              className={inputClass}
              value={app.platform_subtitle}
              onChange={(e) => {
                onChange({ platform_subtitle: e.target.value });
                onPreview({ platform_subtitle: e.target.value });
              }}
            />
          </Field>

          <Field
            label="اللون الأساسي (Primary Brand Color)"
            hint="اللون المعتمد للأزرار النشطة وشارات التمييز"
          >
            <div className="flex items-center gap-3">
              <input
                type="color"
                className="w-14 h-10 rounded-xl border border-white/15 bg-transparent cursor-pointer p-1"
                value={app.primary_color}
                onChange={(e) => {
                  onChange({ primary_color: e.target.value });
                  onPreview({ primary_color: e.target.value });
                }}
              />
              <input
                type="text"
                dir="ltr"
                className={inputClass}
                value={app.primary_color}
                onChange={(e) => {
                  onChange({ primary_color: e.target.value });
                  onPreview({ primary_color: e.target.value });
                }}
              />
            </div>
          </Field>

          <Field
            label="لون التمييز (Accent Highlight Color)"
            hint="اللون المعتمد للتنبيهات والرسوم البيانية البارزة"
          >
            <div className="flex items-center gap-3">
              <input
                type="color"
                className="w-14 h-10 rounded-xl border border-white/15 bg-transparent cursor-pointer p-1"
                value={app.accent_color}
                onChange={(e) => {
                  onChange({ accent_color: e.target.value });
                  onPreview({ accent_color: e.target.value });
                }}
              />
              <input
                type="text"
                dir="ltr"
                className={inputClass}
                value={app.accent_color}
                onChange={(e) => {
                  onChange({ accent_color: e.target.value });
                  onPreview({ accent_color: e.target.value });
                }}
              />
            </div>
          </Field>
        </div>

        <div className="grid sm:grid-cols-2 gap-4 pt-4 border-t border-white/5">
          <Toggle
            checked={app.compact_mode}
            onChange={(compact_mode) => {
              onChange({ compact_mode });
              onPreview({ compact_mode });
            }}
            label="الوضع المدمج (Compact View)"
            description="تقليل الهوامش والمسافات البينية لعرض أكبر قدر من البيانات"
          />
          <Toggle
            checked={app.animations}
            onChange={(animations) => {
              onChange({ animations });
              onPreview({ animations });
            }}
            label="المؤثرات الحركية السلسة (Animations)"
            description="تفعيل الانتقالات والرسوم الحركية أثناء التصفح والتحميل"
          />
        </div>
      </SectionCard>

      {/* Live Preview Card */}
      <div className="rounded-2xl border border-cyan-500/20 p-6 sm:p-7 bg-gradient-to-l from-cyan-500/10 via-transparent to-rose-500/10 relative overflow-hidden">
        <div className="relative z-10 space-y-3">
          <div className="inline-flex items-center gap-2 px-2.5 py-1 rounded-lg text-xs font-bold bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">
            <Eye className="w-3.5 h-3.5" />
            معاينة حية للهوية
          </div>
          <h2 className="text-2xl font-black text-white">{app.platform_title}</h2>
          <p className="text-sm text-slate-300 max-w-xl">{app.platform_subtitle}</p>
          <div className="flex items-center gap-3 pt-2">
            <button
              type="button"
              className="px-4 py-2 rounded-xl font-black text-xs text-slate-950 transition-colors shadow-md"
              style={{ backgroundColor: app.primary_color }}
            >
              زر إجراء رئيسي
            </button>
            <span
              className="px-3 py-1.5 rounded-xl text-xs font-bold text-white border"
              style={{ borderColor: `${app.accent_color}40`, backgroundColor: `${app.accent_color}15` }}
            >
              شارة تنبيه مميزة
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}
