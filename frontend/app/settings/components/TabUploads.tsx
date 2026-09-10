import React from 'react';
import { HardDrive, AlertTriangle, ShieldCheck } from 'lucide-react';
import { PlatformConfig } from '../../../lib/types';
import { Field, SectionCard, inputClass } from './FormControls';

export function TabUploads({
  config,
  onChange,
}: {
  config: PlatformConfig;
  onChange: (values: Partial<PlatformConfig['uploads']>) => void;
}) {
  const u = config.uploads;

  return (
    <div className="space-y-6 animate-fade-in">
      <SectionCard
        title="الحدود القصوى لرفع الملفات (Upload Limits)"
        subtitle="حجم الملفات المسموح برفعه لكل محرك تحليلي لمنع استنزاف ذاكرة الخادم"
      >
        <div className="grid md:grid-cols-3 gap-5">
          <Field
            label="حد ملفات FlowScope (ميغابايت)"
            hint="أقصى حجم لملف CSV أو XLSX لتدفقات Flowmon (1 - 4096 MB)"
          >
            <input
              type="number"
              min={1}
              max={4096}
              className={inputClass}
              value={u.flowscope_max_mb}
              onChange={(e) => onChange({ flowscope_max_mb: Number(e.target.value) })}
            />
          </Field>

          <Field
            label="حد ملفات ThreatScope (ميغابايت)"
            hint="أقصى حجم لملف سجلات XDR والبصمات (1 - 4096 MB)"
          >
            <input
              type="number"
              min={1}
              max={4096}
              className={inputClass}
              value={u.threatscope_max_mb}
              onChange={(e) => onChange({ threatscope_max_mb: Number(e.target.value) })}
            />
          </Field>

          <Field
            label="حد ملفات LogScope (ميغابايت)"
            hint="أقصى حجم لملف سجلات SIEM و Syslog و JSONL (1 - 4096 MB)"
          >
            <input
              type="number"
              min={1}
              max={4096}
              className={inputClass}
              value={u.logscope_max_mb || 100}
              onChange={(e) => onChange({ logscope_max_mb: Number(e.target.value) })}
            />
          </Field>
        </div>
      </SectionCard>

      <SectionCard
        title="حماية وضوابط حزم Excel المضغوطة (ZIP/XLSX Decompression Bomb Protection)"
        subtitle="معايير الأمان لمنع هجمات قنابل الضغط (Zip Bomb) واستنزاف الموارد أثناء فك ملفات XLSX"
      >
        <div className="grid md:grid-cols-3 gap-5">
          <Field
            label="أقصى عدد ملفات داخل حزمة XLSX"
            hint="عدد الأجزاء والملفات الداخلية المسموح بها داخل ملف Excel (20 - 50,000)"
          >
            <input
              type="number"
              min={20}
              max={50000}
              className={inputClass}
              value={u.xlsx_max_files}
              onChange={(e) => onChange({ xlsx_max_files: Number(e.target.value) })}
            />
          </Field>

          <Field
            label="أقصى حجم مفكوك للملف (MB)"
            hint="الحد الأقصى للبيانات بعد فك الضغط في الذاكرة (10 - 8192 MB)"
          >
            <input
              type="number"
              min={10}
              max={8192}
              className={inputClass}
              value={u.xlsx_max_uncompressed_mb}
              onChange={(e) => onChange({ xlsx_max_uncompressed_mb: Number(e.target.value) })}
            />
          </Field>

          <Field
            label="أقصى نسبة ضغط مسموحة (Ratio)"
            hint="حظر الملفات التي تتجاوز نسبة فك ضغط غير معتادة (10 - 2000)"
          >
            <input
              type="number"
              min={10}
              max={2000}
              className={inputClass}
              value={u.xlsx_max_compression_ratio}
              onChange={(e) => onChange({ xlsx_max_compression_ratio: Number(e.target.value) })}
            />
          </Field>
        </div>
      </SectionCard>
    </div>
  );
}
