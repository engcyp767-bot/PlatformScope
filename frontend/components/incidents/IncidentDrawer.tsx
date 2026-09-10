'use client';

import React, { useState, useEffect } from 'react';
import Link from 'next/link';
import {
  X, Shield, AlertTriangle, CheckCircle, Clock, User, FileText,
  Paperclip, ExternalLink, ArrowRight, ArrowLeft, Copy, Check,
  Trash2, Plus, MessageSquare, History, Activity, ShieldAlert,
  Download, Eye, RefreshCw, Layers, Sparkles
} from 'lucide-react';
import { Incident, IncidentStatus, IncidentSeverity, IncidentPriority, EvidenceType, User as UserType } from '../../lib/types';
import { CopilotTab } from './CopilotTab';
import {
  getIncident, updateIncidentStatus, assignIncident,
  updateIncidentPriority, addIncidentNote, addIncidentEvidence,
  removeIncidentEvidence, fetchApi
} from '../../lib/api';

interface IncidentDrawerProps {
  incidentId: string | null;
  isOpen: boolean;
  onClose: () => void;
  onUpdated?: () => void;
  currentUser?: UserType | null;
}

const LIFECYCLE_STEPS: { key: IncidentStatus; label: string; desc: string }[] = [
  { key: 'new', label: 'جديد (New)', desc: 'تم رصد الحادث مبدئياً' },
  { key: 'triaged', label: 'مفروز (Triaged)', desc: 'تم الفرز وتأكيد الأهمية' },
  { key: 'investigating', label: 'قيد التحقيق (Investigating)', desc: 'جمع الأدلة والتحليل الجنائي' },
  { key: 'contained', label: 'تم الاحتواء (Contained)', desc: 'عزل التهديد والحد من انتشاره' },
  { key: 'resolved', label: 'تم الحل (Resolved)', desc: 'معالجة الثغرة وإزالة الأثر' },
  { key: 'closed', label: 'مغلق (Closed)', desc: 'إغلاق الحادث وتوثيق التقرير' },
];

export function IncidentDrawer({ incidentId, isOpen, onClose, onUpdated, currentUser }: IncidentDrawerProps) {
  const [incident, setIncident] = useState<Incident | null>(null);
  const [loading, setLoading] = useState(false);
  const [activeTab, setActiveTab] = useState<'overview' | 'evidence' | 'notes' | 'timeline' | 'audit' | 'copilot'>('overview');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  // Status transition modal
  const [statusModalOpen, setStatusModalOpen] = useState(false);
  const [targetStatus, setTargetStatus] = useState<IncidentStatus>('triaged');
  const [statusReason, setStatusReason] = useState('');
  const [statusSaving, setStatusSaving] = useState(false);

  // Assignment modal
  const [assignModalOpen, setAssignModalOpen] = useState(false);
  const [assigneeUsername, setAssigneeUsername] = useState('');
  const [assignReason, setAssignReason] = useState('');
  const [availableUsers, setAvailableUsers] = useState<string[]>([]);

  // Priority modal
  const [priorityModalOpen, setPriorityModalOpen] = useState(false);
  const [newSeverity, setNewSeverity] = useState<IncidentSeverity>('high');
  const [newAssetCrit, setNewAssetCrit] = useState('high');
  const [newBizImpact, setNewBizImpact] = useState('high');
  const [priorityJustification, setPriorityJustification] = useState('');

  // Add note state
  const [newNote, setNewNote] = useState('');
  const [noteSaving, setNoteSaving] = useState(false);

  // Add evidence modal
  const [evidenceModalOpen, setEvidenceModalOpen] = useState(false);
  const [evidenceType, setEvidenceType] = useState<EvidenceType>('ip');
  const [evidenceName, setEvidenceName] = useState('');
  const [evidenceValue, setEvidenceValue] = useState('');
  const [evidenceNotes, setEvidenceNotes] = useState('');
  const [evidenceFileB64, setEvidenceFileB64] = useState<string | null>(null);
  const [evidenceFileName, setEvidenceFileName] = useState<string | null>(null);
  const [evidenceSaving, setEvidenceSaving] = useState(false);

  const canManage = currentUser?.permissions?.includes('incidents.manage');

  const loadIncidentData = async (id: string) => {
    setLoading(true);
    try {
      const data = await getIncident(id);
      setIncident(data);
    } catch (err) {
      console.error('Failed to load incident details:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (isOpen && incidentId) {
      loadIncidentData(incidentId);
      // Load user list for assignment
      fetchApi('/api/admin/users').then((res) => {
        if (res?.users) {
          setAvailableUsers(res.users.map((u: any) => u.username));
        }
      }).catch(() => {});
    } else {
      setIncident(null);
    }
  }, [isOpen, incidentId]);

  if (!isOpen) return null;

  const copyToClipboard = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const handleStatusChange = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!incident || !statusReason.trim()) return;
    setStatusSaving(true);
    try {
      const updated = await updateIncidentStatus(incident.id, targetStatus, statusReason.trim());
      setIncident(updated);
      setStatusModalOpen(false);
      setStatusReason('');
      onUpdated?.();
    } catch (err: any) {
      alert(err.message || 'فشل تحديث الحالة');
    } finally {
      setStatusSaving(false);
    }
  };

  const handleAssign = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!incident) return;
    try {
      const updated = await assignIncident(incident.id, assigneeUsername || null, assignReason);
      setIncident(updated);
      setAssignModalOpen(false);
      onUpdated?.();
    } catch (err: any) {
      alert(err.message || 'فشل تعيين المحلل');
    }
  };

  const handlePriorityUpdate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!incident || !priorityJustification.trim()) return;
    try {
      const updated = await updateIncidentPriority(incident.id, {
        severity: newSeverity,
        asset_criticality: newAssetCrit,
        business_impact: newBizImpact,
        justification: priorityJustification.trim(),
      });
      setIncident(updated);
      setPriorityModalOpen(false);
      setPriorityJustification('');
      onUpdated?.();
    } catch (err: any) {
      alert(err.message || 'فشل تعديل الأولوية');
    }
  };

  const handleAddNote = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!incident || !newNote.trim()) return;
    setNoteSaving(true);
    try {
      const updated = await addIncidentNote(incident.id, newNote.trim());
      setIncident(updated);
      setNewNote('');
      onUpdated?.();
    } catch (err: any) {
      alert(err.message || 'فشل إضافة الملاحظة');
    } finally {
      setNoteSaving(false);
    }
  };

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setEvidenceFileName(file.name);
    if (!evidenceName) setEvidenceName(file.name);
    const reader = new FileReader();
    reader.onload = () => {
      const result = reader.result as string;
      const base64 = result.split(',')[1];
      setEvidenceFileB64(base64);
    };
    reader.readAsDataURL(file);
  };

  const handleAddEvidence = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!incident || !evidenceName.trim()) return;
    setEvidenceSaving(true);
    try {
      const updated = await addIncidentEvidence(incident.id, {
        evidence_type: evidenceType,
        name: evidenceName.trim(),
        value: evidenceValue.trim() || undefined,
        notes: evidenceNotes.trim() || undefined,
        file_b64: evidenceFileB64 || undefined,
        filename: evidenceFileName || undefined,
      });
      setIncident(updated);
      setEvidenceModalOpen(false);
      setEvidenceName('');
      setEvidenceValue('');
      setEvidenceNotes('');
      setEvidenceFileB64(null);
      setEvidenceFileName(null);
      onUpdated?.();
    } catch (err: any) {
      alert(err.message || 'فشل إضافة الدليل');
    } finally {
      setEvidenceSaving(false);
    }
  };

  const handleRemoveEvidence = async (evidenceId: string) => {
    if (!incident || !confirm('هل أنت متأكد من حذف هذا الدليل الرقمي؟')) return;
    try {
      const updated = await removeIncidentEvidence(incident.id, evidenceId);
      setIncident(updated);
      onUpdated?.();
    } catch (err: any) {
      alert(err.message || 'فشل حذف الدليل');
    }
  };

  // Lifecycle visual state
  const currentStepIdx = LIFECYCLE_STEPS.findIndex((s) => s.key === incident?.status);
  const isRejected = incident?.status === 'rejected';

  return (
    <div className="fixed inset-0 z-50 overflow-hidden bg-black/70 backdrop-blur-sm flex justify-end transition-opacity">
      <div className="w-full max-w-4xl bg-dark-950 border-r border-white/10 h-full flex flex-col shadow-2xl animate-in slide-in-from-left duration-300">
        
        {/* Top Header */}
        <div className="px-6 py-4 border-b border-white/10 bg-dark-900/80 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className={`p-2.5 rounded-xl border ${
              incident?.priority === 'P1' ? 'bg-red-500/20 border-red-500/40 text-red-400' :
              incident?.priority === 'P2' ? 'bg-orange-500/20 border-orange-500/40 text-orange-400' :
              incident?.priority === 'P3' ? 'bg-amber-500/20 border-amber-500/40 text-amber-400' :
              'bg-blue-500/20 border-blue-500/40 text-blue-400'
            }`}>
              <ShieldAlert className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-mono text-sm font-bold text-primary tracking-wide">{incident?.id}</span>
                <span className={`px-2 py-0.5 rounded text-[11px] font-bold uppercase ${
                  incident?.priority === 'P1' ? 'bg-red-500/20 text-red-400 border border-red-500/30' :
                  incident?.priority === 'P2' ? 'bg-orange-500/20 text-orange-400 border border-orange-500/30' :
                  incident?.priority === 'P3' ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30' :
                  'bg-blue-500/20 text-blue-400 border border-blue-500/30'
                }`}>
                  {incident?.priority}
                </span>
                <span className="text-xs text-slate-400 font-mono bg-white/5 px-2 py-0.5 rounded border border-white/10">
                  {incident?.correlation_id}
                </span>
              </div>
              <h2 className="text-lg font-bold text-white mt-0.5 line-clamp-1">{incident?.title || 'تفاصيل الحادث الأمني'}</h2>
            </div>
          </div>

          <div className="flex items-center gap-2">
            {incident && (
              <a
                href={`/api/incidents/${encodeURIComponent(incident.id)}/case-export`}
                download
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-purple-500/10 hover:bg-purple-500/20 border border-purple-500/30 text-xs font-medium text-purple-300 transition-colors shadow-sm shadow-purple-500/10"
                title="تصدير ملف التحقيق الجنائي الرقمي المهيكل مع بيان SHA-256"
              >
                <Download className="w-3.5 h-3.5 text-purple-400" />
                <span>تصدير ملف التحقيق (ZIP)</span>
              </a>
            )}
            {incident?.source_job_id && (
              <Link
                href={`/${incident.source_app}/${incident.source_job_id}`}
                target="_blank"
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-primary/10 hover:bg-primary/20 border border-primary/30 text-xs font-medium text-primary transition-colors"
                title="الانتقال إلى شاشة التحليل الأصلية"
              >
                <ExternalLink className="w-3.5 h-3.5" />
                <span>التحليل الأصلي ({incident.source_app})</span>
              </Link>
            )}
            <button
              onClick={onClose}
              className="p-2 rounded-lg text-slate-400 hover:text-white hover:bg-white/10 transition-colors"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {loading ? (
          <div className="flex-1 flex flex-col items-center justify-center gap-3">
            <div className="w-8 h-8 border-2 border-primary border-t-transparent rounded-full animate-spin"></div>
            <span className="text-xs text-slate-400">جاري استرجاع سجلات الحادث...</span>
          </div>
        ) : incident ? (
          <>
            {/* Lifecycle Visual Stepper */}
            <div className="px-6 py-3.5 bg-dark-900/40 border-b border-white/5">
              {isRejected ? (
                <div className="p-3 rounded-xl bg-red-950/40 border border-red-500/40 flex items-center justify-between">
                  <div className="flex items-center gap-2 text-red-400 text-xs font-bold">
                    <AlertTriangle className="w-4 h-4" />
                    <span>تم رفض الحادث واعتباره إيجابية كاذبة (False Positive / Benign)</span>
                  </div>
                  {canManage && (
                    <button
                      onClick={() => {
                        setTargetStatus('investigating');
                        setStatusModalOpen(true);
                      }}
                      className="text-xs px-2.5 py-1 rounded bg-red-500/20 hover:bg-red-500/30 text-red-300 font-medium"
                    >
                      إعادة فتح للتحقيق
                    </button>
                  )}
                </div>
              ) : (
                <div className="grid grid-cols-6 gap-1">
                  {LIFECYCLE_STEPS.map((step, idx) => {
                    const isPassed = currentStepIdx >= idx;
                    const isCurrent = currentStepIdx === idx;
                    return (
                      <div
                        key={step.key}
                        className={`flex flex-col items-center p-2 rounded-lg text-center transition-all ${
                          isCurrent
                            ? 'bg-primary/20 border border-primary/50 text-white font-bold shadow-md shadow-primary/10'
                            : isPassed
                            ? 'bg-white/5 text-slate-300'
                            : 'opacity-40 text-slate-500'
                        }`}
                      >
                        <div className="flex items-center gap-1 mb-1">
                          <span className={`w-2 h-2 rounded-full ${isCurrent ? 'bg-primary animate-pulse' : isPassed ? 'bg-emerald-400' : 'bg-slate-600'}`}></span>
                          <span className="text-[11px] truncate">{step.label.split(' ')[0]}</span>
                        </div>
                        <span className="text-[9px] text-slate-400 font-mono">0{idx + 1}</span>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>

            {/* Quick Actions Bar */}
            {canManage && (
              <div className="px-6 py-2.5 bg-white/[0.02] border-b border-white/5 flex items-center justify-between text-xs">
                <div className="flex items-center gap-2">
                  <span className="text-slate-400">الإجراءات السريعة:</span>
                  <button
                    onClick={() => {
                      setTargetStatus(incident.status === 'new' ? 'triaged' : incident.status === 'triaged' ? 'investigating' : 'contained');
                      setStatusModalOpen(true);
                    }}
                    className="px-3 py-1.5 rounded-md bg-primary/20 hover:bg-primary/30 text-primary font-medium border border-primary/30 flex items-center gap-1.5"
                  >
                    <RefreshCw className="w-3 h-3" />
                    <span>تغيير الحالة</span>
                  </button>

                  <button
                    onClick={() => {
                      setAssigneeUsername(incident.assigned_to || '');
                      setAssignModalOpen(true);
                    }}
                    className="px-3 py-1.5 rounded-md bg-white/5 hover:bg-white/10 text-slate-300 font-medium border border-white/10 flex items-center gap-1.5"
                  >
                    <User className="w-3 h-3 text-cyan-400" />
                    <span>تعيين لمحلل ({incident.assigned_to || 'غير معين'})</span>
                  </button>

                  <button
                    onClick={() => {
                      setNewSeverity(incident.severity);
                      setNewAssetCrit(incident.asset_criticality || 'medium');
                      setNewBizImpact(incident.business_impact || 'medium');
                      setPriorityModalOpen(true);
                    }}
                    className="px-3 py-1.5 rounded-md bg-white/5 hover:bg-white/10 text-slate-300 font-medium border border-white/10 flex items-center gap-1.5"
                  >
                    <Layers className="w-3 h-3 text-amber-400" />
                    <span>تعديل الأولوية / الخطورة</span>
                  </button>
                </div>

                <div className="flex items-center gap-2">
                  <a
                    href={`/api/incidents/${encodeURIComponent(incident.id)}/case-export`}
                    download
                    className="px-2.5 py-1.5 rounded-md bg-purple-500/20 hover:bg-purple-500/30 text-purple-300 font-medium border border-purple-500/30 flex items-center gap-1.5"
                    title="تصدير حزمة التحقيق الجنائي الرسمية (INC-ID.zip)"
                  >
                    <Download className="w-3 h-3 text-purple-400" />
                    <span>تصدير ملف القضية</span>
                  </a>
                  <button
                    onClick={() => {
                      setTargetStatus('rejected');
                      setStatusModalOpen(true);
                    }}
                    className="px-2.5 py-1.5 rounded-md bg-red-500/10 hover:bg-red-500/20 text-red-400 font-medium border border-red-500/20"
                  >
                    رفض (False Positive)
                  </button>
                </div>
              </div>
            )}

            {/* Navigation Tabs */}
            <div className="flex items-center border-b border-white/10 px-6 bg-dark-900/30 text-xs font-medium">
              <button
                onClick={() => setActiveTab('overview')}
                className={`py-3 px-4 border-b-2 flex items-center gap-1.5 transition-colors ${
                  activeTab === 'overview' ? 'border-primary text-primary font-bold' : 'border-transparent text-slate-400 hover:text-white'
                }`}
              >
                <FileText className="w-3.5 h-3.5" />
                <span>نظرة عامة والكيانات</span>
              </button>
              <button
                onClick={() => setActiveTab('evidence')}
                className={`py-3 px-4 border-b-2 flex items-center gap-1.5 transition-colors ${
                  activeTab === 'evidence' ? 'border-primary text-primary font-bold' : 'border-transparent text-slate-400 hover:text-white'
                }`}
              >
                <Paperclip className="w-3.5 h-3.5" />
                <span>الأدلة الرقمية ({incident.evidence?.length || 0})</span>
              </button>
              <button
                onClick={() => setActiveTab('notes')}
                className={`py-3 px-4 border-b-2 flex items-center gap-1.5 transition-colors ${
                  activeTab === 'notes' ? 'border-primary text-primary font-bold' : 'border-transparent text-slate-400 hover:text-white'
                }`}
              >
                <MessageSquare className="w-3.5 h-3.5" />
                <span>ملاحظات التحقيق ({incident.notes?.length || 0})</span>
              </button>
              <button
                onClick={() => setActiveTab('timeline')}
                className={`py-3 px-4 border-b-2 flex items-center gap-1.5 transition-colors ${
                  activeTab === 'timeline' ? 'border-primary text-primary font-bold' : 'border-transparent text-slate-400 hover:text-white'
                }`}
              >
                <Clock className="w-3.5 h-3.5" />
                <span>الخط الزمني ({incident.timeline?.length || 0})</span>
              </button>
              <button
                onClick={() => setActiveTab('audit')}
                className={`py-3 px-4 border-b-2 flex items-center gap-1.5 transition-colors ${
                  activeTab === 'audit' ? 'border-primary text-primary font-bold' : 'border-transparent text-slate-400 hover:text-white'
                }`}
              >
                <History className="w-3.5 h-3.5" />
                <span>سجل التدقيق الأمني ({incident.audit?.length || 0})</span>
              </button>
              <button
                onClick={() => setActiveTab('copilot')}
                className={`py-3 px-4 border-b-2 flex items-center gap-1.5 transition-colors relative ${
                  activeTab === 'copilot' ? 'border-amber-400 text-amber-400 font-bold bg-amber-500/5' : 'border-transparent text-slate-400 hover:text-white'
                }`}
              >
                <Sparkles className="w-3.5 h-3.5 text-amber-400" />
                <span>المساعد الذكي (AI Copilot)</span>
                <span className="text-[9px] px-1.5 py-0.2 rounded bg-amber-500/20 text-amber-300 border border-amber-500/30 font-mono font-bold uppercase">
                  AI
                </span>
              </button>
            </div>

            {/* Tab Contents */}
            <div className="flex-1 overflow-y-auto p-6 space-y-6">

              {/* OVERVIEW TAB */}
              {activeTab === 'overview' && (
                <div className="space-y-6">
                  {/* Summary Card */}
                  <div className="p-4 rounded-xl bg-white/[0.02] border border-white/10 space-y-3">
                    <h3 className="text-sm font-bold text-white">الوصف وسياق الهجوم</h3>
                    <p className="text-xs text-slate-300 leading-relaxed whitespace-pre-wrap">
                      {incident.description || 'لا يوجد وصف مدخل لهذا الحادث.'}
                    </p>
                  </div>

                  {/* Metadata Grid */}
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                    <div className="p-3 rounded-lg bg-white/[0.02] border border-white/5">
                      <span className="text-[10px] text-slate-400 block mb-1">المحرك المصدر</span>
                      <span className="text-xs font-bold text-white uppercase">{incident.source_app}</span>
                    </div>
                    <div className="p-3 rounded-lg bg-white/[0.02] border border-white/5">
                      <span className="text-[10px] text-slate-400 block mb-1">أهمية الأصل المتأثر</span>
                      <span className="text-xs font-bold text-amber-400 capitalize">{incident.asset_criticality}</span>
                    </div>
                    <div className="p-3 rounded-lg bg-white/[0.02] border border-white/5">
                      <span className="text-[10px] text-slate-400 block mb-1">الأثر على العمليات</span>
                      <span className="text-xs font-bold text-orange-400 capitalize">{incident.business_impact}</span>
                    </div>
                    <div className="p-3 rounded-lg bg-white/[0.02] border border-white/5">
                      <span className="text-[10px] text-slate-400 block mb-1">مستوى الثقة في الكشف</span>
                      <span className="text-xs font-mono font-bold text-emerald-400">{incident.confidence}%</span>
                    </div>
                  </div>

                  {/* Entities Section */}
                  <div className="space-y-2">
                    <h3 className="text-sm font-bold text-white flex items-center justify-between">
                      <span>الكيانات المستهدفة والمرتبطة (Target Entities)</span>
                      <span className="text-xs text-slate-400 font-mono">{incident.entities?.length || 0} كيان</span>
                    </h3>
                    {incident.entities && incident.entities.length > 0 ? (
                      <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                        {incident.entities.map((entity, idx) => (
                          <div
                            key={idx}
                            className="flex items-center justify-between p-2.5 rounded-lg bg-white/5 border border-white/10 text-xs font-mono"
                          >
                            <span className="text-slate-200 truncate">{entity}</span>
                            <button
                              onClick={() => copyToClipboard(entity, `ent_${idx}`)}
                              className="text-slate-400 hover:text-primary transition-colors p-1"
                              title="نسخ"
                            >
                              {copiedKey === `ent_${idx}` ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                            </button>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <div className="p-4 rounded-lg bg-white/[0.02] border border-dashed border-white/10 text-center text-xs text-slate-400">
                        لم يتم ربط كيانات بهذا الحادث بعد.
                      </div>
                    )}
                  </div>

                  {/* MITRE ATT&CK Matrix */}
                  <div className="space-y-2">
                    <h3 className="text-sm font-bold text-white">إطار MITRE ATT&CK المرتبط</h3>
                    <div className="flex flex-wrap gap-2">
                      {incident.mitre_tactics && incident.mitre_tactics.length > 0 ? (
                        incident.mitre_tactics.map((tactic, idx) => (
                          <span
                            key={idx}
                            className="px-2.5 py-1 rounded-md bg-purple-500/10 border border-purple-500/30 text-purple-300 text-xs font-mono"
                          >
                            {tactic}
                          </span>
                        ))
                      ) : (
                        <span className="text-xs text-slate-400">لا توجد تاكتيكات مصنفة حالياً.</span>
                      )}
                    </div>
                  </div>
                </div>
              )}

              {/* EVIDENCE TAB */}
              {activeTab === 'evidence' && (
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <span className="text-xs text-slate-400">
                      صندوق الأدلة الرقمية الجنائية مع التحقق من سلامة التجزئة SHA-256.
                    </span>
                    {canManage && (
                      <button
                        onClick={() => setEvidenceModalOpen(true)}
                        className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-primary hover:bg-primary/90 text-dark-950 font-bold text-xs transition-colors shadow-sm"
                      >
                        <Plus className="w-4 h-4" />
                        <span>إرفاق دليل جديد</span>
                      </button>
                    )}
                  </div>

                  {incident.evidence && incident.evidence.length > 0 ? (
                    <div className="space-y-3">
                      {incident.evidence.map((item) => (
                        <div
                          key={item.id}
                          className="p-4 rounded-xl bg-white/[0.02] border border-white/10 hover:border-white/20 transition-all space-y-2"
                        >
                          <div className="flex items-start justify-between gap-3">
                            <div className="flex items-center gap-2.5">
                              <div className="p-2 rounded-lg bg-white/5 border border-white/10 text-primary">
                                <Paperclip className="w-4 h-4" />
                              </div>
                              <div>
                                <div className="flex items-center gap-2">
                                  <span className="text-xs font-bold text-white">{item.name}</span>
                                  <span className="px-2 py-0.5 rounded text-[10px] font-mono uppercase bg-white/5 text-slate-400 border border-white/10">
                                    {item.evidence_type}
                                  </span>
                                </div>
                                <span className="text-[10px] text-slate-400 font-mono">
                                  أضيف بواسطة {item.added_by} في {new Date(item.added_at).toLocaleString('en-US')}
                                </span>
                              </div>
                            </div>

                            <div className="flex items-center gap-1.5">
                              {item.file_path && (
                                <a
                                  href={`/api/incidents/${incident.id}/evidence/${item.id}/download`}
                                  target="_blank"
                                  rel="noopener noreferrer"
                                  className="p-1.5 rounded bg-white/5 hover:bg-white/10 text-slate-300 transition-colors"
                                  title="تحميل الملف"
                                >
                                  <Download className="w-3.5 h-3.5" />
                                </a>
                              )}
                              {canManage && (
                                <button
                                  onClick={() => handleRemoveEvidence(item.id)}
                                  className="p-1.5 rounded bg-red-500/10 hover:bg-red-500/20 text-red-400 transition-colors"
                                  title="حذف الدليل"
                                >
                                  <Trash2 className="w-3.5 h-3.5" />
                                </button>
                              )}
                            </div>
                          </div>

                          {item.value && (
                            <div className="p-2 rounded bg-black/40 border border-white/5 text-xs font-mono text-cyan-300 break-all flex items-center justify-between">
                              <span>{item.value}</span>
                              <button
                                onClick={() => copyToClipboard(item.value || '', `val_${item.id}`)}
                                className="p-1 text-slate-400 hover:text-white"
                              >
                                {copiedKey === `val_${item.id}` ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                              </button>
                            </div>
                          )}

                          {item.sha256 && (
                            <div className="flex items-center gap-2 text-[10px] text-slate-400 font-mono">
                              <span className="font-bold text-slate-500">SHA-256:</span>
                              <span className="truncate">{item.sha256}</span>
                              <button
                                onClick={() => copyToClipboard(item.sha256 || '', `sha_${item.id}`)}
                                className="text-slate-400 hover:text-white"
                              >
                                {copiedKey === `sha_${item.id}` ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                              </button>
                            </div>
                          )}

                          {item.notes && (
                            <p className="text-xs text-slate-400 italic bg-white/[0.01] p-2 rounded">
                              {item.notes}
                            </p>
                          )}
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="p-8 rounded-xl bg-white/[0.01] border border-dashed border-white/10 text-center space-y-2">
                      <Paperclip className="w-8 h-8 text-slate-500 mx-auto" />
                      <p className="text-xs text-slate-400">لم يتم إرفاق أدلة رقمية بهذا الحادث بعد.</p>
                    </div>
                  )}
                </div>
              )}

              {/* NOTES TAB */}
              {activeTab === 'notes' && (
                <div className="space-y-4">
                  {canManage && (
                    <form onSubmit={handleAddNote} className="space-y-2.5 p-4 rounded-xl bg-white/[0.02] border border-white/10">
                      <label className="text-xs font-bold text-white block">إضافة ملاحظة تحقيق جديدة</label>
                      <textarea
                        value={newNote}
                        onChange={(e) => setNewNote(e.target.value)}
                        placeholder="اكتب ملاحظاتك الجنائية أو الإجراءات المتخذة هنا..."
                        rows={3}
                        required
                        className="w-full bg-dark-900 border border-white/10 rounded-lg p-3 text-xs text-white placeholder:text-slate-500 focus:outline-none focus:border-primary"
                      />
                      <div className="flex justify-end">
                        <button
                          type="submit"
                          disabled={noteSaving || !newNote.trim()}
                          className="px-4 py-1.5 rounded-lg bg-primary hover:bg-primary/90 disabled:opacity-50 text-dark-950 font-bold text-xs transition-colors"
                        >
                          {noteSaving ? 'جاري الحفظ...' : 'نشر الملاحظة'}
                        </button>
                      </div>
                    </form>
                  )}

                  <div className="space-y-3">
                    {incident.notes && incident.notes.length > 0 ? (
                      incident.notes.map((note) => (
                        <div key={note.id} className="p-3.5 rounded-xl bg-white/[0.02] border border-white/10 space-y-1.5">
                          <div className="flex items-center justify-between text-xs">
                            <span className="font-bold text-primary flex items-center gap-1.5">
                              <User className="w-3.5 h-3.5" />
                              <span>{note.author}</span>
                            </span>
                            <span className="text-[10px] text-slate-400 font-mono">
                              {new Date(note.created_at).toLocaleString('en-US')}
                            </span>
                          </div>
                          <p className="text-xs text-slate-300 leading-relaxed whitespace-pre-wrap">{note.note_text}</p>
                        </div>
                      ))
                    ) : (
                      <div className="p-8 rounded-xl bg-white/[0.01] border border-dashed border-white/10 text-center text-xs text-slate-400">
                        لا توجد ملاحظات مدونة في هذا الحادث بعد.
                      </div>
                    )}
                  </div>
                </div>
              )}

              {/* TIMELINE TAB */}
              {activeTab === 'timeline' && (
                <div className="space-y-4">
                  <div className="relative pl-6 space-y-6 before:absolute before:inset-0 before:left-[11px] before:w-0.5 before:bg-white/10">
                    {incident.timeline && incident.timeline.length > 0 ? (
                      incident.timeline.map((item) => (
                        <div key={item.id} className="relative flex items-start gap-4 text-xs">
                          <div className="w-6 h-6 rounded-full bg-dark-900 border-2 border-primary flex items-center justify-center -ml-[35px] text-primary z-10 shadow-sm">
                            <Activity className="w-3 h-3" />
                          </div>
                          <div className="flex-1 p-3 rounded-lg bg-white/[0.02] border border-white/10 space-y-1">
                            <div className="flex items-center justify-between">
                              <span className="font-bold text-white">{item.action}</span>
                              <span className="text-[10px] text-slate-400 font-mono">
                                {new Date(item.timestamp).toLocaleString('en-US')}
                              </span>
                            </div>
                            <p className="text-slate-300 text-xs">{item.details}</p>
                            <span className="text-[10px] text-slate-500 font-mono block">بواسطة: {item.actor}</span>
                          </div>
                        </div>
                      ))
                    ) : (
                      <div className="p-4 text-center text-xs text-slate-400">لا توجد أحداث مسجلة بعد.</div>
                    )}
                  </div>
                </div>
              )}

              {/* AUDIT TAB */}
              {activeTab === 'audit' && (
                <div className="space-y-3">
                  <span className="text-xs text-slate-400 block mb-2">
                    سجل التدقيق الشامل (Who, What, When, Before, After, Reason):
                  </span>
                  <div className="space-y-2">
                    {incident.audit && incident.audit.length > 0 ? (
                      incident.audit.map((aud) => (
                        <div key={aud.id} className="p-3 rounded-lg bg-white/[0.02] border border-white/5 space-y-2 text-xs">
                          <div className="flex items-center justify-between font-mono text-[11px]">
                            <div className="flex items-center gap-2">
                              <span className="font-bold text-primary">{aud.action}</span>
                              <span className="text-slate-400">بواسطة: {aud.actor}</span>
                            </div>
                            <span className="text-slate-400">{new Date(aud.timestamp).toLocaleString('en-US')}</span>
                          </div>
                          <div className="bg-black/30 p-2 rounded border border-white/5 font-mono text-[11px] text-slate-300">
                            <strong>السبب: </strong>{aud.reason}
                          </div>
                          {(aud.before_state || aud.after_state) && (
                            <div className="grid grid-cols-2 gap-2 text-[10px] font-mono">
                              <div className="p-1.5 rounded bg-red-950/20 border border-red-500/20 text-red-300 truncate">
                                <strong>قبل: </strong>{aud.before_state || 'N/A'}
                              </div>
                              <div className="p-1.5 rounded bg-emerald-950/20 border border-emerald-500/20 text-emerald-300 truncate">
                                <strong>بعد: </strong>{aud.after_state || 'N/A'}
                              </div>
                            </div>
                          )}
                        </div>
                      ))
                    ) : (
                      <div className="p-4 text-center text-xs text-slate-400">لا توجد سجلات تدقيق مسجلة.</div>
                    )}
                  </div>
                </div>
              )}

              {/* COPILOT TAB */}
              {activeTab === 'copilot' && (
                <CopilotTab
                  incident={incident}
                  currentUser={currentUser}
                  onNoteAdded={() => {
                    loadIncidentData(incident.id);
                    onUpdated?.();
                  }}
                />
              )}

            </div>
          </>
        ) : null}

      </div>

      {/* STATUS CHANGE MODAL */}
      {statusModalOpen && (
        <div className="fixed inset-0 z-60 bg-black/80 flex items-center justify-center p-4">
          <form onSubmit={handleStatusChange} className="w-full max-w-md bg-dark-900 border border-white/15 rounded-xl p-6 space-y-4 shadow-2xl">
            <h3 className="text-base font-bold text-white flex items-center gap-2">
              <RefreshCw className="w-4 h-4 text-primary" />
              <span>تغيير حالة الحادث الأمني</span>
            </h3>

            <div>
              <label className="text-xs font-bold text-slate-300 block mb-1.5">الحالة الجديدة المستهدفة</label>
              <select
                value={targetStatus}
                onChange={(e) => setTargetStatus(e.target.value as IncidentStatus)}
                className="w-full bg-dark-950 border border-white/10 rounded-lg p-2.5 text-xs text-white focus:outline-none focus:border-primary"
              >
                <option value="new">جديد (New)</option>
                <option value="triaged">مفروز ومصنف (Triaged)</option>
                <option value="investigating">قيد التحقيق الجنائي (Investigating)</option>
                <option value="contained">تم الاحتواء والعزل (Contained)</option>
                <option value="resolved">تم الحل والمعالجة (Resolved)</option>
                <option value="closed">مغلق نهائياً (Closed)</option>
                <option value="rejected">مرفوض - إيجابية كاذبة (Rejected / False Positive)</option>
              </select>
            </div>

            <div>
              <label className="text-xs font-bold text-slate-300 block mb-1.5">سبب تغيير الحالة (إلزامي للتدقيق)</label>
              <textarea
                value={statusReason}
                onChange={(e) => setStatusReason(e.target.value)}
                placeholder="وضح المبرر الأمني لتغيير الحالة..."
                rows={3}
                required
                className="w-full bg-dark-950 border border-white/10 rounded-lg p-2.5 text-xs text-white focus:outline-none focus:border-primary"
              />
            </div>

            <div className="flex justify-end gap-2 pt-2">
              <button
                type="button"
                onClick={() => setStatusModalOpen(false)}
                className="px-4 py-2 rounded-lg bg-white/5 hover:bg-white/10 text-slate-300 text-xs font-medium"
              >
                إلغاء
              </button>
              <button
                type="submit"
                disabled={statusSaving || !statusReason.trim()}
                className="px-4 py-2 rounded-lg bg-primary hover:bg-primary/90 text-dark-950 font-bold text-xs"
              >
                {statusSaving ? 'جاري الحفظ...' : 'تأكيد التغيير'}
              </button>
            </div>
          </form>
        </div>
      )}

      {/* ASSIGN ANALYST MODAL */}
      {assignModalOpen && (
        <div className="fixed inset-0 z-60 bg-black/80 flex items-center justify-center p-4">
          <form onSubmit={handleAssign} className="w-full max-w-md bg-dark-900 border border-white/15 rounded-xl p-6 space-y-4 shadow-2xl">
            <h3 className="text-base font-bold text-white flex items-center gap-2">
              <User className="w-4 h-4 text-cyan-400" />
              <span>تعيين الحادث لمحلل SOC</span>
            </h3>

            <div>
              <label className="text-xs font-bold text-slate-300 block mb-1.5">اسم المحلل</label>
              <select
                value={assigneeUsername}
                onChange={(e) => setAssigneeUsername(e.target.value)}
                className="w-full bg-dark-950 border border-white/10 rounded-lg p-2.5 text-xs text-white focus:outline-none focus:border-primary"
              >
                <option value="">-- غير معين (إلغاء التعيين) --</option>
                {availableUsers.map((u) => (
                  <option key={u} value={u}>{u}</option>
                ))}
              </select>
            </div>

            <div>
              <label className="text-xs font-bold text-slate-300 block mb-1.5">ملاحظات التكليف (اختياري)</label>
              <input
                type="text"
                value={assignReason}
                onChange={(e) => setAssignReason(e.target.value)}
                placeholder="توجيهات أو سبب التكليف..."
                className="w-full bg-dark-950 border border-white/10 rounded-lg p-2.5 text-xs text-white focus:outline-none focus:border-primary"
              />
            </div>

            <div className="flex justify-end gap-2 pt-2">
              <button
                type="button"
                onClick={() => setAssignModalOpen(false)}
                className="px-4 py-2 rounded-lg bg-white/5 hover:bg-white/10 text-slate-300 text-xs font-medium"
              >
                إلغاء
              </button>
              <button
                type="submit"
                className="px-4 py-2 rounded-lg bg-primary hover:bg-primary/90 text-dark-950 font-bold text-xs"
              >
                تأكيد التعيين
              </button>
            </div>
          </form>
        </div>
      )}

      {/* PRIORITY ADJUSTMENT MODAL */}
      {priorityModalOpen && (
        <div className="fixed inset-0 z-60 bg-black/80 flex items-center justify-center p-4">
          <form onSubmit={handlePriorityUpdate} className="w-full max-w-md bg-dark-900 border border-white/15 rounded-xl p-6 space-y-4 shadow-2xl">
            <h3 className="text-base font-bold text-white flex items-center gap-2">
              <Layers className="w-4 h-4 text-amber-400" />
              <span>تعديل مستوى الخطورة والأولوية</span>
            </h3>

            <div className="grid grid-cols-3 gap-2">
              <div>
                <label className="text-[11px] font-bold text-slate-300 block mb-1">الخطورة</label>
                <select
                  value={newSeverity}
                  onChange={(e) => setNewSeverity(e.target.value as IncidentSeverity)}
                  className="w-full bg-dark-950 border border-white/10 rounded-lg p-2 text-xs text-white"
                >
                  <option value="critical">Critical</option>
                  <option value="high">High</option>
                  <option value="medium">Medium</option>
                  <option value="low">Low</option>
                  <option value="info">Info</option>
                </select>
              </div>
              <div>
                <label className="text-[11px] font-bold text-slate-300 block mb-1">حرجية الأصل</label>
                <select
                  value={newAssetCrit}
                  onChange={(e) => setNewAssetCrit(e.target.value)}
                  className="w-full bg-dark-950 border border-white/10 rounded-lg p-2 text-xs text-white"
                >
                  <option value="mission_critical">Mission Critical</option>
                  <option value="high">High</option>
                  <option value="medium">Medium</option>
                  <option value="low">Low</option>
                </select>
              </div>
              <div>
                <label className="text-[11px] font-bold text-slate-300 block mb-1">أثر العمليات</label>
                <select
                  value={newBizImpact}
                  onChange={(e) => setNewBizImpact(e.target.value)}
                  className="w-full bg-dark-950 border border-white/10 rounded-lg p-2 text-xs text-white"
                >
                  <option value="high">High</option>
                  <option value="medium">Medium</option>
                  <option value="low">Low</option>
                  <option value="none">None</option>
                </select>
              </div>
            </div>

            <div>
              <label className="text-xs font-bold text-slate-300 block mb-1.5">التبرير الأمني للتعديل (إلزامي للتدقيق)</label>
              <textarea
                value={priorityJustification}
                onChange={(e) => setPriorityJustification(e.target.value)}
                placeholder="وضح سبب إعادة تقييم الخطورة والأولوية..."
                rows={3}
                required
                className="w-full bg-dark-950 border border-white/10 rounded-lg p-2.5 text-xs text-white focus:outline-none focus:border-primary"
              />
            </div>

            <div className="flex justify-end gap-2 pt-2">
              <button
                type="button"
                onClick={() => setPriorityModalOpen(false)}
                className="px-4 py-2 rounded-lg bg-white/5 hover:bg-white/10 text-slate-300 text-xs font-medium"
              >
                إلغاء
              </button>
              <button
                type="submit"
                disabled={!priorityJustification.trim()}
                className="px-4 py-2 rounded-lg bg-primary hover:bg-primary/90 text-dark-950 font-bold text-xs"
              >
                حفظ التعديل
              </button>
            </div>
          </form>
        </div>
      )}

      {/* ADD EVIDENCE MODAL */}
      {evidenceModalOpen && (
        <div className="fixed inset-0 z-60 bg-black/80 flex items-center justify-center p-4">
          <form onSubmit={handleAddEvidence} className="w-full max-w-lg bg-dark-900 border border-white/15 rounded-xl p-6 space-y-4 shadow-2xl">
            <h3 className="text-base font-bold text-white flex items-center gap-2">
              <Paperclip className="w-4 h-4 text-primary" />
              <span>إرفاق دليل رقمي جنائي</span>
            </h3>

            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="text-xs font-bold text-slate-300 block mb-1.5">نوع الدليل</label>
                <select
                  value={evidenceType}
                  onChange={(e) => setEvidenceType(e.target.value as EvidenceType)}
                  className="w-full bg-dark-950 border border-white/10 rounded-lg p-2.5 text-xs text-white"
                >
                  <option value="ip">عنوان IP مشبوه</option>
                  <option value="domain">نطاق خبيث (Domain)</option>
                  <option value="url">رابط C2 URL</option>
                  <option value="hash">بصمة تجزئة (Hash)</option>
                  <option value="file">ملف جنائي / عينة برمجية</option>
                  <option value="log_snippet">اقتباس سجل (Log Snippet)</option>
                  <option value="cve">ثغرة أمنية (CVE)</option>
                  <option value="other">أخرى</option>
                </select>
              </div>
              <div>
                <label className="text-xs font-bold text-slate-300 block mb-1.5">اسم / عنوان الدليل</label>
                <input
                  type="text"
                  value={evidenceName}
                  onChange={(e) => setEvidenceName(e.target.value)}
                  placeholder="مثال: C2 Beaconing IP"
                  required
                  className="w-full bg-dark-950 border border-white/10 rounded-lg p-2.5 text-xs text-white"
                />
              </div>
            </div>

            {evidenceType === 'file' ? (
              <div>
                <label className="text-xs font-bold text-slate-300 block mb-1.5">رفع الملف (يحفظ في Evidence Vault)</label>
                <input
                  type="file"
                  onChange={handleFileUpload}
                  required
                  className="w-full text-xs text-slate-400 file:mr-4 file:py-2 file:px-4 file:rounded-lg file:border-0 file:text-xs file:font-semibold file:bg-primary file:text-dark-950 hover:file:bg-primary/90"
                />
              </div>
            ) : (
              <div>
                <label className="text-xs font-bold text-slate-300 block mb-1.5">القيمة / المحتوى</label>
                <textarea
                  value={evidenceValue}
                  onChange={(e) => setEvidenceValue(e.target.value)}
                  placeholder="أدخل عنوان IP أو البصمة أو نص السجل..."
                  rows={3}
                  className="w-full bg-dark-950 border border-white/10 rounded-lg p-2.5 text-xs text-white font-mono"
                />
              </div>
            )}

            <div>
              <label className="text-xs font-bold text-slate-300 block mb-1.5">ملاحظات المحلل حول الدليل</label>
              <input
                type="text"
                value={evidenceNotes}
                onChange={(e) => setEvidenceNotes(e.target.value)}
                placeholder="سياق الحصول على الدليل..."
                className="w-full bg-dark-950 border border-white/10 rounded-lg p-2.5 text-xs text-white"
              />
            </div>

            <div className="flex justify-end gap-2 pt-2">
              <button
                type="button"
                onClick={() => setEvidenceModalOpen(false)}
                className="px-4 py-2 rounded-lg bg-white/5 hover:bg-white/10 text-slate-300 text-xs font-medium"
              >
                إلغاء
              </button>
              <button
                type="submit"
                disabled={evidenceSaving || !evidenceName.trim()}
                className="px-4 py-2 rounded-lg bg-primary hover:bg-primary/90 text-dark-950 font-bold text-xs"
              >
                {evidenceSaving ? 'جاري الإرفاق...' : 'إرفاق الدليل'}
              </button>
            </div>
          </form>
        </div>
      )}

    </div>
  );
}
