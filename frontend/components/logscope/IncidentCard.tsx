'use client';

import React from 'react';
import {
  ShieldAlert,
  Clock,
  User,
  Laptop,
  ArrowRight,
  Target,
  FileSearch,
  CheckCircle2,
  AlertTriangle,
} from 'lucide-react';
import { RiskBadge } from '../RiskBadge';

export interface IncidentData {
  incident_id: string;
  title_ar: string;
  description_ar: string;
  start_time: string;
  end_time: string;
  source_ips: string[];
  target_ips?: string[];
  usernames: string[];
  devices: string[];
  event_count: number;
  detection_ids: string[];
  mitre_tactics: string[];
  mitre_techniques: string[];
  risk_score: number;
  confidence_score: number;
  conclusion_level: string;
  severity: string;
  timeline_events?: Array<{
    time?: string;
    event_id?: string;
    user?: string;
    src?: string;
    status?: string;
    action?: string;
  }>;
  recommendations?: string[];
}

interface IncidentCardProps {
  incident: IncidentData;
  onSelectIncident: (incident: IncidentData) => void;
  onFilterEntity?: (type: 'user' | 'ip' | 'device', value: string) => void;
}

export function translateConclusion(level: string): { label: string; color: string } {
  const norm = (level || '').toLowerCase();
  switch (norm) {
    case 'confirmed':
      return { label: 'مؤكد بالأدلة الجنائية', color: 'bg-rose-500/20 text-rose-300 border-rose-500/40' };
    case 'likely_successful':
      return { label: 'يرجح نجاح الهجوم', color: 'bg-amber-500/20 text-amber-300 border-amber-500/40' };
    case 'correlated_suspicious':
      return { label: 'نشاط مترابط مشبوه', color: 'bg-purple-500/20 text-purple-300 border-purple-500/40' };
    case 'likely_malicious':
      return { label: 'يرجح كونه خبيثاً', color: 'bg-orange-500/20 text-orange-300 border-orange-500/40' };
    case 'suspicious':
      return { label: 'مشبوه وقيد الفحص', color: 'bg-yellow-500/20 text-yellow-300 border-yellow-500/40' };
    case 'observed':
    default:
      return { label: 'نشاط مرصود', color: 'bg-slate-500/20 text-slate-300 border-slate-500/40' };
  }
}

export function IncidentCard({ incident, onSelectIncident, onFilterEntity }: IncidentCardProps) {
  const conclusion = translateConclusion(incident.conclusion_level);

  return (
    <div className="rounded-2xl border border-white/10 bg-gradient-to-b from-dark-900/80 to-dark-950/90 hover:border-emerald-500/40 transition-all p-5 shadow-xl hover:shadow-2xl flex flex-col justify-between group">
      <div className="space-y-4">
        {/* Header: ID, Conclusion, Risk Badge */}
        <div className="flex items-start justify-between gap-3 flex-wrap">
          <div className="flex items-center gap-2.5 flex-wrap">
            <span className="px-2.5 py-1 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 font-mono text-xs font-bold">
              {incident.incident_id}
            </span>
            <span className={`px-2.5 py-1 rounded-xl text-xs font-bold border ${conclusion.color}`}>
              {conclusion.label}
            </span>
          </div>

          <div className="flex items-center gap-2">
            <div className="flex flex-col items-end">
              <span className="text-[10px] text-slate-400 font-medium">نسبة الموثوقية:</span>
              <span className="text-xs font-extrabold text-cyan-400 font-mono">{incident.confidence_score}%</span>
            </div>
            <RiskBadge score={incident.risk_score} level={incident.severity} />
          </div>
        </div>

        {/* Title & Forensic Summary */}
        <div>
          <h4 className="text-base font-extrabold text-white group-hover:text-emerald-300 transition-colors leading-snug" dir="auto">
            {incident.title_ar}
          </h4>
          <p className="text-xs text-slate-300 mt-2 line-clamp-2 leading-relaxed" dir="auto">
            {incident.description_ar}
          </p>
        </div>

        {/* Temporal Span & Event Count */}
        <div className="flex items-center gap-4 text-xs text-slate-400 bg-black/30 p-2.5 rounded-xl border border-white/5 flex-wrap">
          <div className="flex items-center gap-1.5 font-mono">
            <Clock className="w-3.5 h-3.5 text-emerald-400" />
            <span>{incident.start_time || '—'}</span>
            {incident.end_time && incident.end_time !== incident.start_time && (
              <>
                <span className="text-slate-600">←</span>
                <span>{incident.end_time}</span>
              </>
            )}
          </div>
          <div className="mr-auto font-bold text-slate-200">
            <span>{incident.event_count}</span>{' '}
            <span className="text-slate-400 font-normal">أحداث مساهمة</span>
          </div>
        </div>

        {/* Targeted & Affected Entities */}
        <div className="space-y-1.5 pt-1">
          <div className="text-[11px] font-bold text-slate-400">الكيانات المتأثرة والمهاجمة:</div>
          <div className="flex flex-wrap gap-1.5">
            {incident.usernames?.map((u, i) => (
              <button
                key={i}
                type="button"
                onClick={(e) => {
                  e.stopPropagation();
                  onFilterEntity?.('user', u);
                }}
                className="inline-flex items-center gap-1 px-2 py-1 rounded-lg bg-emerald-500/10 hover:bg-emerald-500/20 border border-emerald-500/20 text-[11px] text-emerald-300 font-medium transition-colors"
                title="تصفية أحداث هذا الحساب"
              >
                <User className="w-3 h-3" />
                <span>{u}</span>
              </button>
            ))}

            {incident.source_ips?.map((ip, i) => (
              <button
                key={i}
                type="button"
                onClick={(e) => {
                  e.stopPropagation();
                  onFilterEntity?.('ip', ip);
                }}
                className="inline-flex items-center gap-1 px-2 py-1 rounded-lg bg-cyan-500/10 hover:bg-cyan-500/20 border border-cyan-500/20 text-[11px] text-cyan-300 font-mono transition-colors"
                title="تصفية أحداث هذا العنوان"
              >
                <Target className="w-3 h-3" />
                <span>{ip}</span>
              </button>
            ))}

            {incident.devices?.map((dev, i) => (
              <button
                key={i}
                type="button"
                onClick={(e) => {
                  e.stopPropagation();
                  onFilterEntity?.('device', dev);
                }}
                className="inline-flex items-center gap-1 px-2 py-1 rounded-lg bg-purple-500/10 hover:bg-purple-500/20 border border-purple-500/20 text-[11px] text-purple-300 font-mono transition-colors"
                title="تصفية أحداث هذا الجهاز"
              >
                <Laptop className="w-3 h-3" />
                <span>{dev}</span>
              </button>
            ))}
          </div>
        </div>

        {/* MITRE Badges */}
        {incident.mitre_techniques && incident.mitre_techniques.length > 0 && (
          <div className="flex flex-wrap gap-1 pt-1">
            {incident.mitre_techniques.slice(0, 3).map((t, idx) => (
              <span
                key={idx}
                className="px-2 py-0.5 rounded bg-white/5 border border-white/10 text-[10px] text-slate-300 font-mono"
              >
                {t}
              </span>
            ))}
            {incident.mitre_techniques.length > 3 && (
              <span className="px-1.5 py-0.5 rounded bg-white/5 text-[10px] text-slate-400">
                +{incident.mitre_techniques.length - 3} تقنيات أخرى
              </span>
            )}
          </div>
        )}
      </div>

      {/* Footer Action */}
      <div className="mt-5 pt-4 border-t border-white/10 flex items-center justify-between">
        <span className="text-[11px] text-slate-400">
          المرحلة: <span className="text-white font-bold">{incident.mitre_tactics?.[0] || 'Initial Activity'}</span>
        </span>

        <button
          type="button"
          onClick={() => onSelectIncident(incident)}
          className="flex items-center gap-1.5 px-4 py-2 rounded-xl bg-emerald-500 hover:bg-emerald-400 text-dark-950 text-xs font-extrabold transition-all shadow-md hover:shadow-emerald-500/20"
        >
          <FileSearch className="w-3.5 h-3.5" />
          <span>بدء التحقيق الجنائي</span>
        </button>
      </div>
    </div>
  );
}
