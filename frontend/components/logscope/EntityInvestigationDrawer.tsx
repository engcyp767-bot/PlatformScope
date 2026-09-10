'use client';

import React, { useEffect, useState } from 'react';
import {
  X,
  User,
  Target,
  Laptop,
  Clock,
  Radio,
  ShieldAlert,
  ShieldCheck,
  ListFilter,
  RefreshCw,
  Layers,
  ArrowRight,
  Globe,
  AlertTriangle,
} from 'lucide-react';

interface EntityInvestigationDrawerProps {
  jobId: string;
  entity: {
    type: 'user' | 'ip' | 'device';
    value: string;
  } | null;
  enrichment?: any;
  onClose: () => void;
  onFilterByEntity: (type: 'user' | 'ip' | 'device', value: string) => void;
}

export function EntityInvestigationDrawer({
  jobId,
  entity,
  enrichment,
  onClose,
  onFilterByEntity,
}: EntityInvestigationDrawerProps) {
  const [loading, setLoading] = useState<boolean>(false);
  const [profile, setProfile] = useState<any>(null);

  useEffect(() => {
    if (!entity || !jobId) {
      setProfile(null);
      return;
    }

    let isMounted = true;
    setLoading(true);

    const fetchEntityProfile = async () => {
      try {
        const res = await fetch(
          `/api/logscope/jobs/${jobId}/entities/${entity.type}/${encodeURIComponent(entity.value)}`
        );
        if (res.ok) {
          const data = await res.json();
          if (isMounted) setProfile(data);
        } else {
          if (isMounted) {
            setProfile({
              type: entity.type,
              value: entity.value,
              total_events: '—',
              critical_events: '—',
              high_events: '—',
            });
          }
        }
      } catch (err) {
        if (isMounted) {
          setProfile({
            type: entity.type,
            value: entity.value,
            total_events: '—',
            critical_events: '—',
            high_events: '—',
          });
        }
      } finally {
        if (isMounted) setLoading(false);
      }
    };

    fetchEntityProfile();
    return () => {
      isMounted = false;
    };
  }, [entity, jobId]);

  if (!entity) return null;

  const typeIcons = {
    user: <User className="w-5 h-5 text-emerald-400" />,
    ip: <Target className="w-5 h-5 text-cyan-400" />,
    device: <Laptop className="w-5 h-5 text-purple-400" />,
  };

  const typeLabels = {
    user: 'حساب مستخدم (User Account)',
    ip: 'عنوان IP / مضيف شبكي (Network IP)',
    device: 'جهاز / جدار حماية (Device/Host)',
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-md p-4 grid place-items-center animate-in fade-in duration-200">
      <div
        className="glass-panel w-full max-w-2xl max-h-[90vh] overflow-hidden flex flex-col border-emerald-500/30 shadow-2xl rounded-2xl bg-dark-950"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="p-5 border-b border-white/10 flex items-center justify-between gap-4 bg-gradient-to-r from-dark-900 to-dark-950">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-white/5 border border-white/10">
              {typeIcons[entity.type]}
            </div>
            <div>
              <div className="text-xs text-slate-400 font-bold">{typeLabels[entity.type]}</div>
              <h3 className="font-extrabold text-white text-lg font-mono mt-0.5" dir="ltr">
                {entity.value}
              </h3>
            </div>
          </div>

          <button
            type="button"
            onClick={onClose}
            className="p-2 rounded-xl bg-white/5 hover:bg-white/10 border border-white/10 text-slate-300 hover:text-white transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content */}
        <div className="p-6 overflow-y-auto space-y-6 flex-1 text-slate-200 text-xs">
          {loading ? (
            <div className="p-12 text-center space-y-3">
              <RefreshCw className="w-6 h-6 animate-spin text-emerald-500 mx-auto" />
              <p className="text-slate-400">جاري استخراج السجل الجنائي للكيان من قاعدة البيانات...</p>
            </div>
          ) : (
            <>
              {/* Metrics */}
              <div className="grid grid-cols-3 gap-3">
                <div className="p-3.5 rounded-xl bg-black/30 border border-white/10 space-y-1">
                  <div className="text-[10px] text-slate-400 font-bold">إجمالي الأحداث المسجلة</div>
                  <div className="text-base font-bold text-white font-mono">
                    {profile?.total_events ?? '—'}
                  </div>
                </div>

                <div className="p-3.5 rounded-xl bg-black/30 border border-white/10 space-y-1">
                  <div className="text-[10px] text-slate-400 font-bold">أحداث حرجة (Critical)</div>
                  <div className="text-base font-bold text-rose-400 font-mono">
                    {profile?.critical_events ?? '0'}
                  </div>
                </div>

                <div className="p-3.5 rounded-xl bg-black/30 border border-white/10 space-y-1">
                  <div className="text-[10px] text-slate-400 font-bold">أحداث مرتفعة (High)</div>
                  <div className="text-base font-bold text-amber-400 font-mono">
                    {profile?.high_events ?? '0'}
                  </div>
                </div>
              </div>

              {/* Time Span */}
              {(profile?.first_seen || profile?.last_seen) && (
                <div className="p-3.5 rounded-xl bg-black/20 border border-white/5 space-y-2">
                  <div className="font-bold text-slate-400 flex items-center gap-1.5">
                    <Clock className="w-3.5 h-3.5 text-emerald-400" />
                    <span>فترة الظهور والنشاط:</span>
                  </div>
                  <div className="flex items-center justify-between text-slate-300 font-mono text-[11px]">
                    <div>أول نشاط: {profile.first_seen || '—'}</div>
                    <div>آخر نشاط: {profile.last_seen || '—'}</div>
                  </div>
                </div>
              )}

              {/* Destinations & Ports if IP */}
              {entity.type === 'ip' && profile?.destinations?.length > 0 && (
                <div className="space-y-2">
                  <div className="font-bold text-slate-400">الوجهات المتصل بها ({profile.destinations.length}):</div>
                  <div className="flex flex-wrap gap-1.5 max-h-24 overflow-y-auto">
                    {profile.destinations.map((d: string, idx: number) => (
                      <span
                        key={idx}
                        className="px-2 py-0.5 rounded bg-white/5 border border-white/10 font-mono text-[11px] text-slate-300"
                      >
                        {d}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {profile?.ports?.length > 0 && (
                <div className="space-y-2">
                  <div className="font-bold text-slate-400">المنافذ المرتبطة بالنشاط:</div>
                  <div className="flex flex-wrap gap-1.5">
                    {profile.ports.map((p: string, idx: number) => (
                      <span
                        key={idx}
                        className="px-2 py-0.5 rounded bg-cyan-500/10 border border-cyan-500/20 font-mono text-[11px] text-cyan-300"
                      >
                        {p}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* Associated Incidents */}
              {profile?.incident_ids?.length > 0 && (
                <div className="space-y-2">
                  <div className="font-bold text-rose-400 flex items-center gap-1.5">
                    <ShieldAlert className="w-3.5 h-3.5" />
                    <span>الحوادث الأمنية المرتبطة بهذا الكيان:</span>
                  </div>
                  <div className="flex flex-wrap gap-1.5">
                    {profile.incident_ids.map((incId: string, idx: number) => (
                      <span
                        key={idx}
                        className="px-2 py-0.5 rounded bg-rose-500/20 border border-rose-500/30 font-mono font-bold text-[11px] text-rose-300"
                      >
                        {incId}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* Threat Intelligence & Reputation for IP Entities */}
              {entity.type === 'ip' && (() => {
                const intel = enrichment || profile?.enrichment;
                if (!intel) {
                  return (
                    <div className="p-3.5 rounded-xl bg-black/20 border border-white/5 flex items-center gap-2.5 text-slate-400 text-xs">
                      <Globe className="w-4 h-4 text-slate-500 shrink-0" />
                      <span>لم يتم استخراج استخبارات سمعة خارجية لهذا العنوان بعد (استخدم زر «بدء فحص السمعة» من اللوحة العلوية).</span>
                    </div>
                  );
                }

                if (intel.reason) {
                  return (
                    <div className="p-3.5 rounded-xl bg-blue-950/20 border border-blue-500/30 flex items-center gap-3">
                      <div className="p-2 rounded-lg bg-blue-500/10 text-blue-400 border border-blue-500/20 shrink-0">
                        <ShieldCheck className="w-4 h-4" />
                      </div>
                      <div>
                        <div className="font-bold text-slate-200 text-xs">نطاق شبكي محلي / خاص (RFC 1918)</div>
                        <div className="text-[11px] text-slate-400 mt-0.5">{intel.reason} — مستثنى من استعلامات السمعة الخارجية حفاظاً على الخصوصية التشغيلية.</div>
                      </div>
                    </div>
                  );
                }

                const vt = intel.virustotal;
                const abuse = intel.abuseipdb;
                const shodan = intel.shodan;
                const isMalicious = (vt?.malicious > 0) || (abuse?.score >= 50);
                const isSuspicious = (vt?.suspicious > 0) || (abuse?.score >= 20);
                const verdictText = isMalicious ? 'تهديد مؤكد / خبيث' : isSuspicious ? 'مشبوه / يحتاج مراجعة' : (vt || abuse) ? 'سليم / لا توجد بلاغات' : 'غير مكتمل';
                const verdictColor = isMalicious ? 'text-rose-400 bg-rose-500/15 border-rose-500/30' : isSuspicious ? 'text-amber-400 bg-amber-500/15 border-amber-500/30' : 'text-emerald-400 bg-emerald-500/15 border-emerald-500/30';

                return (
                  <div className="rounded-2xl border border-cyan-500/30 bg-gradient-to-b from-cyan-950/20 via-dark-900 to-dark-900 p-4 space-y-3">
                    <div className="flex items-center justify-between border-b border-white/10 pb-2.5">
                      <div className="flex items-center gap-2 font-bold text-white text-xs">
                        <Globe className="w-4 h-4 text-cyan-400" />
                        <span>استخبارات وسمعة العنوان الخارجية (Threat Intelligence)</span>
                      </div>
                      <span className={`px-2.5 py-0.5 rounded-full text-[11px] font-bold border ${verdictColor}`}>
                        {verdictText}
                      </span>
                    </div>

                    <div className="grid sm:grid-cols-2 gap-3">
                      {/* VirusTotal */}
                      {vt ? (
                        <div className="p-3 rounded-xl bg-black/30 border border-white/10 space-y-2">
                          <div className="flex items-center justify-between">
                            <span className="font-bold text-white text-xs flex items-center gap-1.5">
                              <ShieldAlert className="w-3.5 h-3.5 text-blue-400" />
                              <span>VirusTotal</span>
                            </span>
                            <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded ${vt.malicious > 0 ? 'bg-rose-500/20 text-rose-300' : 'bg-emerald-500/20 text-emerald-300'}`}>
                              {vt.verdict || (vt.malicious > 0 ? 'ضار' : 'سليم')}
                            </span>
                          </div>
                          <div className="grid grid-cols-3 gap-1.5 text-center pt-1 font-mono text-[11px]">
                            <div className="p-1.5 rounded bg-white/5">
                              <div className="text-[9px] text-slate-400">كشف ضار</div>
                              <div className="font-bold text-rose-400">{vt.malicious ?? 0}</div>
                            </div>
                            <div className="p-1.5 rounded bg-white/5">
                              <div className="text-[9px] text-slate-400">مشبوه</div>
                              <div className="font-bold text-amber-400">{vt.suspicious ?? 0}</div>
                            </div>
                            <div className="p-1.5 rounded bg-white/5">
                              <div className="text-[9px] text-slate-400">السمعة</div>
                              <div className="font-bold text-slate-200">{vt.reputation ?? 0}</div>
                            </div>
                          </div>
                        </div>
                      ) : (
                        <div className="p-3 rounded-xl bg-black/30 border border-white/10 space-y-1.5 opacity-60">
                          <div className="text-xs font-bold text-slate-400 flex items-center gap-1.5">
                            <ShieldAlert className="w-3.5 h-3.5" />
                            <span>VirusTotal</span>
                          </div>
                          <div className="text-[11px] text-slate-400">غير متاح أو لم يتم الفحص</div>
                        </div>
                      )}

                      {/* AbuseIPDB */}
                      {abuse ? (
                        <div className="p-3 rounded-xl bg-black/30 border border-white/10 space-y-2">
                          <div className="flex items-center justify-between">
                            <span className="font-bold text-white text-xs flex items-center gap-1.5">
                              <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
                              <span>AbuseIPDB</span>
                            </span>
                            <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded ${abuse.score >= 50 ? 'bg-rose-500/20 text-rose-300' : abuse.score > 0 ? 'bg-amber-500/20 text-amber-300' : 'bg-emerald-500/20 text-emerald-300'}`}>
                              ثقة البلاغات: {abuse.score ?? 0}%
                            </span>
                          </div>
                          <div className="space-y-1 text-[11px] text-slate-300 pt-1">
                            <div className="flex justify-between">
                              <span className="text-slate-400">عدد البلاغات:</span>
                              <span className="font-bold font-mono text-white">{abuse.total_reports ?? 0} بلاغ</span>
                            </div>
                            {abuse.usage_type && (
                              <div className="flex justify-between">
                                <span className="text-slate-400">نوع الاستخدام:</span>
                                <span className="text-slate-200 truncate max-w-[140px]">{abuse.usage_type}</span>
                              </div>
                            )}
                            {abuse.domain && (
                              <div className="flex justify-between">
                                <span className="text-slate-400">النطاق:</span>
                                <span className="font-mono text-cyan-300 truncate max-w-[140px]">{abuse.domain}</span>
                              </div>
                            )}
                          </div>
                        </div>
                      ) : (
                        <div className="p-3 rounded-xl bg-black/30 border border-white/10 space-y-1.5 opacity-70">
                          <div className="text-xs font-bold text-slate-400 flex items-center gap-1.5">
                            <AlertTriangle className="w-3.5 h-3.5 text-slate-500" />
                            <span>AbuseIPDB</span>
                          </div>
                          <div className="text-[11px] text-slate-400">
                            غير مفعل في المنصة (يتطلب إضافة مفتاح API في صفحة الإعدادات).
                          </div>
                        </div>
                      )}
                    </div>

                    {/* Shodan InternetDB */}
                    {shodan && (
                      <div className="p-3 rounded-xl bg-black/30 border border-white/10 space-y-2">
                        <div className="flex items-center justify-between">
                          <span className="font-bold text-white text-xs flex items-center gap-1.5">
                            <Globe className="w-3.5 h-3.5 text-cyan-400" />
                            <span>Shodan InternetDB</span>
                          </span>
                          {shodan.ports?.length > 0 ? (
                            <span className="text-[10px] font-bold px-1.5 py-0.5 rounded bg-amber-500/20 text-amber-300">
                              {shodan.ports.length} منافذ مفتوحة
                            </span>
                          ) : (
                            <span className="text-[10px] font-bold px-1.5 py-0.5 rounded bg-emerald-500/20 text-emerald-300">
                              سليم — لا توجد منافذ مكشوفة
                            </span>
                          )}
                        </div>
                        {shodan.ports?.length > 0 ? (
                          <div className="flex items-center gap-1.5 flex-wrap">
                            <span className="text-[10px] text-slate-400">المنافذ المفتوحة:</span>
                            {shodan.ports.map((port: number) => (
                              <span key={port} className="px-1.5 py-0.5 rounded bg-cyan-500/10 text-cyan-300 font-mono text-[10px] border border-cyan-500/20">
                                {port}
                              </span>
                            ))}
                          </div>
                        ) : (
                          <div className="text-[11px] text-slate-400">
                            لم يرصد Shodan InternetDB أي منافذ خدمة عامة أو خدمات ويب مكشوفة لهذا العنوان.
                          </div>
                        )}
                        {shodan.vulns?.length > 0 && (
                          <div className="flex items-center gap-1.5 flex-wrap pt-1 border-t border-white/5">
                            <span className="text-[10px] text-rose-400 font-bold">الثغرات المرصودة:</span>
                            {shodan.vulns.slice(0, 6).map((cve: string) => (
                              <span key={cve} className="px-1.5 py-0.5 rounded bg-rose-500/10 text-rose-300 font-mono text-[10px] border border-rose-500/20">
                                {cve}
                              </span>
                            ))}
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                );
              })()}
            </>
          )}
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-white/10 bg-dark-900 flex items-center justify-between">
          <button
            type="button"
            onClick={() => {
              onFilterByEntity(entity.type, entity.value);
              onClose();
            }}
            className="flex items-center gap-2 px-4 py-2 rounded-xl bg-emerald-500 hover:bg-emerald-400 text-dark-950 font-bold text-xs transition-all shadow-md"
          >
            <ListFilter className="w-4 h-4" />
            <span>تصفية وعرض جميع أحداث هذا الكيان في الجدول</span>
          </button>

          <button
            type="button"
            onClick={onClose}
            className="px-4 py-2 rounded-xl bg-white/5 hover:bg-white/10 border border-white/10 text-slate-200 text-xs font-bold transition-colors"
          >
            إغلاق
          </button>
        </div>
      </div>
    </div>
  );
}
