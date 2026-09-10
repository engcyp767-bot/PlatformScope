import React from 'react';
import { ToggleLeft, Shield, Layers, FileCheck, RefreshCw, MessageSquare } from 'lucide-react';
import { PlatformConfig } from '../../../lib/types';
import { Toggle, SectionCard } from './FormControls';

export function TabFeatures({
  config,
  onChange,
}: {
  config: PlatformConfig;
  onChange: (values: Partial<PlatformConfig['features']>) => void;
}) {
  const f = config.features;

  const featureList: Array<{
    key: keyof PlatformConfig['features'];
    label: string;
    description: string;
  }> = [
    {
      key: 'flowscope_enabled',
      label: 'تشغيل وحدة FlowScope',
      description: 'تمكين واجهات وتحليلات تدفقات الشبكة Flowmon و ADS',
    },
    {
      key: 'threatscope_enabled',
      label: 'تشغيل وحدة ThreatScope',
      description: 'تمكين واجهات وفحص سجلات XDR والبصمات الرقمية',
    },
    {
      key: 'logscope_enabled',
      label: 'تشغيل وحدة LogScope',
      description: 'تمكين واجهات وتحقيقات سجلات SIEM وكواشف المجالات الأمنية',
    },
    {
      key: 'report_preview',
      label: 'معاينة تقارير Word كـ PDF',
      description: 'تمكين المعاينة اللحظية السريعة للتقارير قبل التصدير النهائي',
    },
    {
      key: 'excel_export',
      label: 'تصدير مصنفات Excel (.xlsx)',
      description: 'السماح بتصدير جداول البيانات الجنائية كمصنفات Excel كاملة',
    },
    {
      key: 'force_refresh',
      label: 'السماح بفرض التحديث الخارجي',
      description: 'إتاحة خيار تجاوز الكاش المحلي وطلب السمعة مباشرة من المصدر',
    },
    {
      key: 'analyst_feedback',
      label: 'ملاحظات المحلل والتعلم التراكمي',
      description: 'تمكين أزرار تقييم المحلل وتغذية النموذج بنتائج التحقيق',
    },
  ];

  return (
    <div className="space-y-6 animate-fade-in">
      <SectionCard
        title="مفاتيح الميزات والخصائص المركزية (Platform Feature Flags)"
        subtitle="التحكم اللحظي في تفعيل أو تعطيل محركات المنصة ووظائف التصدير والمعاينة المتقدمة"
      >
        <div className="grid md:grid-cols-2 gap-4">
          {featureList.map((item) => (
            <Toggle
              key={item.key}
              checked={Boolean(f[item.key])}
              onChange={(val) => onChange({ [item.key]: val })}
              label={item.label}
              description={item.description}
            />
          ))}
        </div>
      </SectionCard>
    </div>
  );
}
