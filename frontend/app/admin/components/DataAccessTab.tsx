'use client';

import React from 'react';
import { Shield, Users, Layers, Info, CheckCircle2, ShieldAlert } from 'lucide-react';
import { ScopeInfo, User, Group, Role } from '../../../lib/types';

interface DataAccessTabProps {
  scopes: ScopeInfo[];
  users: User[];
  groups: Group[];
  roles: Role[];
}

export function DataAccessTab({ scopes, users, groups, roles }: DataAccessTabProps) {
  const scopeDetails: Record<
    string,
    {
      level: number;
      badgeColor: string;
      bgGradient: string;
      description: string;
      recommendation: string;
    }
  > = {
    own: {
      level: 1,
      badgeColor: 'bg-slate-500/20 text-slate-300 border-slate-500/30',
      bgGradient: 'from-slate-900/40 to-slate-950/40',
      description: 'يقتصر وصول المستخدم على البيانات والحوادث والمهام التي أنشأها بنفسه فقط.',
      recommendation: 'مناسب للمستخدمين المقيدين أو المتدربين أو الأطراف الخارجية.',
    },
    own_shared: {
      level: 2,
      badgeColor: 'bg-blue-500/20 text-blue-300 border-blue-500/30',
      bgGradient: 'from-blue-900/20 to-dark-900',
      description:
        'يرى المستخدم بياناته الخاصة، بالإضافة إلى أي حوادث أو أصول قام محللون آخرون بمشاركتها معه بالاسم أو مع مجموعته.',
      recommendation: 'النطاق القياسي الموصى به للمحللين والمشاهدين العاديين.',
    },
    group: {
      level: 3,
      badgeColor: 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30',
      bgGradient: 'from-emerald-900/20 to-dark-900',
      description:
        'يرى المستخدم بياناته الخاصة وبيانات جميع مجموعات العمل الأمنية التي ينتمي إليها.',
      recommendation: 'مناسب لفرق العمل التخصصية مثل SOC Tier 1 و Incident Responders.',
    },
    department: {
      level: 4,
      badgeColor: 'bg-cyan-500/20 text-cyan-300 border-cyan-500/30',
      bgGradient: 'from-cyan-900/20 to-dark-900',
      description:
        'يرى المستخدم كافة بيانات وسجلات قسمه بالكامل (مثل: قسم العمليات الأمنية أو إدارة المخاطر).',
      recommendation: 'مناسب لرؤساء الأقسام والمشرفين (Supervisors).',
    },
    organization: {
      level: 5,
      badgeColor: 'bg-amber-500/20 text-amber-300 border-amber-500/30',
      bgGradient: 'from-amber-900/20 to-dark-900',
      description: 'يرى المستخدم كافة سجلات وبيانات المنشأة بالكامل عبر كل الأقسام.',
      recommendation: 'مناسب لمدراء الأمن السيبراني (CISO) والمراجعين الداخليين.',
    },
    all: {
      level: 6,
      badgeColor: 'bg-purple-500/20 text-purple-300 border-purple-500/30',
      bgGradient: 'from-purple-900/30 via-dark-900 to-dark-900',
      description: 'وصول سيادي شامل وغير مقيد لجميع بيانات وسجلات المنصة.',
      recommendation: 'مخصص حصرياً لمدير النظام الفعلي (Administrator).',
    },
  };

  return (
    <div className="space-y-6">
      {/* Overview Banner */}
      <div className="glass-panel p-6 rounded-2xl border border-white/10 bg-gradient-to-r from-purple-900/10 via-dark-900 to-dark-900">
        <div className="flex items-start gap-4">
          <div className="w-12 h-12 rounded-2xl bg-amber-500/10 border border-amber-500/20 flex items-center justify-center text-amber-400 shrink-0">
            <ShieldAlert className="w-6 h-6" />
          </div>
          <div>
            <h2 className="text-base font-bold text-white flex items-center gap-2">
              <span>هيكلية نطاق البيانات والحوكمة (Data Scopes Architecture)</span>
              <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-amber-500/20 text-amber-300 border border-amber-500/30">
                6 مستويات هرمية
              </span>
            </h2>
            <p className="text-xs text-slate-400 mt-1 leading-relaxed">
              تعتمد المنصة نظام تحكم صارم يعتمد نموذج <strong>«الرفض التلقائي (Deny by Default)»</strong>.
              يحدد نطاق البيانات الحدود التنظيمية والجغرافية لما يُسمح للمستخدم برؤيته على مستوى الخادم (Server-Side Enforcement)، لمنع ثغرات BOLA و IDOR.
            </p>
          </div>
        </div>
      </div>

      {/* Scope Hierarchy Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {scopes.map((s) => {
          const meta = scopeDetails[s.scope] || {
            level: 1,
            badgeColor: 'bg-white/10 text-white border-white/20',
            bgGradient: 'from-dark-900 to-dark-950',
            description: s.description || '',
            recommendation: '',
          };

          const usersInScope = users.filter((u) => (u.data_scope || 'own_shared') === s.scope);

          return (
            <div
              key={s.scope}
              className={`glass-panel p-5 rounded-2xl border border-white/10 flex flex-col justify-between bg-gradient-to-b ${meta.bgGradient} hover:border-white/20 transition-all`}
            >
              <div>
                <div className="flex items-center justify-between gap-2 mb-3">
                  <span
                    className={`px-2 py-0.5 rounded-lg text-[10px] font-bold border font-mono ${meta.badgeColor}`}
                  >
                    مستوى {meta.level} — {s.scope}
                  </span>
                  <span className="text-[11px] font-mono text-slate-400">
                    {usersInScope.length} مستخدمين
                  </span>
                </div>

                <h3 className="text-base font-bold text-white flex items-center gap-2">
                  <span>{s.label_ar}</span>
                </h3>

                <p className="text-xs text-slate-300 mt-2 leading-relaxed">
                  {meta.description}
                </p>

                <div className="mt-3 p-2.5 rounded-xl bg-black/40 border border-white/5 text-[11px] text-slate-400">
                  <span className="font-bold text-slate-300 block mb-0.5">التوصية الأمنية:</span>
                  <span>{meta.recommendation}</span>
                </div>
              </div>

              {/* Users list preview */}
              <div className="mt-4 pt-3 border-t border-white/5">
                <span className="text-[10px] text-slate-400 block mb-1.5 font-bold">
                  المستخدمون في هذا النطاق:
                </span>
                <div className="flex flex-wrap gap-1 max-h-20 overflow-y-auto">
                  {usersInScope.map((u) => (
                    <span
                      key={u.id}
                      className="px-2 py-0.5 rounded text-[10px] bg-white/5 text-slate-300 border border-white/10 font-mono"
                    >
                      {u.username}
                    </span>
                  ))}
                  {usersInScope.length === 0 && (
                    <span className="text-[10px] text-slate-500 italic">لا يوجد مستخدمون حالياً</span>
                  )}
                </div>
              </div>
            </div>
          );
        })}
      </div>

      {/* Scope vs Sharing Guide */}
      <div className="p-5 rounded-2xl bg-white/5 border border-white/10 space-y-3">
        <h3 className="text-sm font-bold text-white flex items-center gap-2">
          <Info className="w-4 h-4 text-purple-400" />
          <span>الفرق بين «نطاق البيانات» و«مشاركة الموارد»:</span>
        </h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs text-slate-300">
          <div className="p-4 rounded-xl bg-purple-500/10 border border-purple-500/20 space-y-1.5">
            <span className="font-bold text-purple-300 block">نطاق البيانات (Data Scope) — خط الأساس التنظيمي:</span>
            <p className="text-slate-400 text-[11px] leading-relaxed">
              يحدد المدى العام الذي يمكن للمستخدم البحث والاستعلام والتحقيق فيه بشكل تلقائي بحكم موقعه الوظيفي وقسمه.
            </p>
          </div>
          <div className="p-4 rounded-xl bg-amber-500/10 border border-amber-500/20 space-y-1.5">
            <span className="font-bold text-amber-300 block">مشاركة الموارد (Resource Sharing) — الاستثناء التعاوني:</span>
            <p className="text-slate-400 text-[11px] leading-relaxed">
              إجراء صريح من المحلل يمنح مستخدماً أو مجموعة صلاحية الاطلاع على مورد محدد (حادث، أصل، تقرير) خارج نطاقهم بمدة صلاحية محددة (TTL).
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}

