import React from 'react';
import { FileText, Shield, FileCheck, Layers } from 'lucide-react';
import { PlatformConfig } from '../../../lib/types';
import { Field, Toggle, SectionCard, inputClass, selectClass } from './FormControls';

export function TabReports({
  config,
  onChange,
}: {
  config: PlatformConfig;
  onChange: (values: Partial<PlatformConfig['reports']>) => void;
}) {
  const r = config.reports;

  return (
    <div className="space-y-6 animate-fade-in">
      <SectionCard
        title="هوية وتصنيف التقارير الرسمية"
        subtitle="البيانات المطبوعة على ترويسة تقارير Word و Excel ومعاينة PDF المعتمدة"
      >
        <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-5">
          <Field
            label="اسم المنظمة / الجهة"
            hint="يظهر في أعلى صفحات التقارير والصفحة الافتتاحية"
          >
            <input
              type="text"
              className={inputClass}
              value={r.organization_name}
              onChange={(e) => onChange({ organization_name: e.target.value })}
              placeholder="الهيئة الوطنية للأمن السيبراني"
            />
          </Field>

          <Field
            label="درجة التصنيف الأمني (Classification)"
            hint="شارة التصنيف الأمني في رأس وتذييل الصفحات"
          >
            <input
              type="text"
              className={inputClass}
              value={r.classification}
              onChange={(e) => onChange({ classification: e.target.value })}
              placeholder="للاستخدام الداخلي / سري"
            />
          </Field>

          <Field
            label="المسمى المهني للمحلل (Analyst Title)"
            hint="المسمى المطبوع في خانة توقيع المحلل المعد للتقرير"
          >
            <input
              type="text"
              className={inputClass}
              value={r.analyst_title}
              onChange={(e) => onChange({ analyst_title: e.target.value })}
              placeholder="محلل الأمن السيبراني (SOC Analyst)"
            />
          </Field>
        </div>
      </SectionCard>

      <SectionCard
        title="محتوى التقرير وسقف النتائج والتوصيات"
        subtitle="التحكم في عمق البيانات المدرجة في الملحق التنفيذي للتقرير"
      >
        <div className="grid md:grid-cols-3 gap-5">
          <Field
            label="محرك تحويل ومعاينة Word إلى PDF"
            hint="المحرك المستخدم لتوليد المعاينة السريعة داخل المتصفح"
          >
            <select
              className={selectClass}
              value={r.preview_engine}
              onChange={(e) => onChange({ preview_engine: e.target.value })}
            >
              <option value="auto">تلقائي (Microsoft Word ثم LibreOffice)</option>
              <option value="word">Microsoft Word المحلي (Windows)</option>
              <option value="libreoffice">LibreOffice (Linux / Portable)</option>
            </select>
          </Field>

          <Field
            label="أقصى عدد نتائج ذات أولوية (Top Findings)"
            hint="عدد التهديدات الحرجة المدرجة في جدول الملخص (3 - 100)"
          >
            <input
              type="number"
              min={3}
              max={100}
              className={inputClass}
              value={r.top_findings}
              onChange={(e) => onChange({ top_findings: Number(e.target.value) })}
            />
          </Field>

          <Field
            label="أقصى عدد توصيات إجرائية (Recommendations)"
            hint="عدد التوصيات التشغيلية المعروضة لفريق الاستجابة (1 - 30)"
          >
            <input
              type="number"
              min={1}
              max={30}
              className={inputClass}
              value={r.recommendations}
              onChange={(e) => onChange({ recommendations: Number(e.target.value) })}
            />
          </Field>
        </div>

        <div className="grid sm:grid-cols-2 gap-4 pt-4 border-t border-white/5">
          <Toggle
            checked={r.include_ai_analysis}
            onChange={(include_ai_analysis) => onChange({ include_ai_analysis })}
            label="تضمين استنتاجات الذكاء الاصطناعي"
            description="إدراج الخلاصة التفسيرية للنموذج في قسم التقرير التنفيذي"
          />
          <Toggle
            checked={r.include_source_results}
            onChange={(include_source_results) => onChange({ include_source_results })}
            label="تضمين نتائج فحص السمعة والمصادر الخارجية"
            description="إدراج تفاصيل تصنيفات VirusTotal و AbuseIPDB في الملحق"
          />
        </div>
      </SectionCard>
    </div>
  );
}
