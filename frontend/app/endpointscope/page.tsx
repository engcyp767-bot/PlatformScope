'use client';

import React, { useEffect, useState } from 'react';
import {
  Shield,
  ShieldCheck,
  ShieldAlert,
  Server,
  Activity,
  AlertTriangle,
  Play,
  RotateCw,
  Search,
  Filter,
  Plus,
  Lock,
  Unlock,
  Radio,
  Terminal,
  Cpu,
  HardDrive,
  Network,
  Ban,
  X,
  ExternalLink,
  CheckCircle2,
  AlertCircle,
  Eye,
  Trash2,
  Sparkles,
} from 'lucide-react';
import { useTranslation } from '../../lib/i18n';
import { fetchApi } from '../../lib/api';
import { EditionUpgradeModal } from '../../components/EditionUpgradeModal';

interface EndpointAgent {
  agent_id: string;
  hostname: string;
  os_type: string;
  os_version: string;
  agent_version: string;
  ip_addresses: string[];
  mac_addresses: string[];
  state: 'online' | 'offline' | 'degraded' | 'isolated';
  last_heartbeat: string;
  first_seen: string;
  tags: string[];
  group: string;
  risk_score: number;
  active_alerts: number;
}

interface EndpointEvent {
  event_id: string;
  agent_id: string;
  hostname: string;
  event_type: string;
  timestamp: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  process_name?: string;
  command_line?: string;
  details?: Record<string, any>;
}

interface DashboardStats {
  agents: Record<string, number>;
  total_agents: number;
  total_events: number;
  critical_events_24h: number;
  pending_actions: number;
}

export default function EndpointScopePage() {
  const { t, lang } = useTranslation();
  const [agents, setAgents] = useState<EndpointAgent[]>([]);
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [stateFilter, setStateFilter] = useState<string>('all');
  
  // Selected Agent for Detailed Inspection
  const [selectedAgent, setSelectedAgent] = useState<EndpointAgent | null>(null);
  const [agentEvents, setAgentEvents] = useState<EndpointEvent[]>([]);
  const [loadingEvents, setLoadingEvents] = useState(false);
  
  // Host Scan Modal / State
  const [scanResult, setScanResult] = useState<any | null>(null);
  const [isScanning, setIsScanning] = useState(false);
  const [scanModalOpen, setScanModalOpen] = useState(false);

  // Response Action States
  const [actionMsg, setActionMsg] = useState<{ type: 'success' | 'error'; text: string } | null>(null);
  const [actionInProgress, setActionInProgress] = useState(false);
  const [killPid, setKillPid] = useState('');

  // Edition & Upgrade Modal
  const [upgradeModalOpen, setUpgradeModalOpen] = useState(false);
  const [currentEdition, setCurrentEdition] = useState<string>('Community');

  const loadData = async () => {
    setLoading(true);
    try {
      const [agentsRes, statsRes, editionRes] = await Promise.all([
        fetchApi('/api/v1/endpoint/agents').catch(() => ({ data: { agents: [] } })),
        fetchApi('/api/v1/endpoint/stats').catch(() => ({ data: null })),
        fetchApi('/api/v1/edition').catch(() => ({ data: null })),
      ]);

      const agentsList = agentsRes?.data?.agents || (Array.isArray(agentsRes?.data) ? agentsRes.data : []);
      setAgents(agentsList);
      if (statsRes?.data) setStats(statsRes.data);
      if (editionRes?.data?.edition) setCurrentEdition(editionRes.data.edition);
    } catch (err) {
      console.error('Failed to load endpoint data', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 15000);
    return () => clearInterval(interval);
  }, []);

  const openAgentDetails = async (agent: EndpointAgent) => {
    setSelectedAgent(agent);
    setLoadingEvents(true);
    try {
      const res = await fetchApi(`/api/v1/endpoint/agents/${agent.agent_id}`);
      if (res?.data?.recent_events) {
        setAgentEvents(res.data.recent_events);
      } else {
        setAgentEvents([]);
      }
    } catch (err) {
      console.error(err);
      setAgentEvents([]);
    } finally {
      setLoadingEvents(false);
    }
  };

  const handleTriggerHostScan = async () => {
    setIsScanning(true);
    setScanResult(null);
    setScanModalOpen(true);
    try {
      const res = await fetchApi('/api/v1/endpoint/monitor/scan', { method: 'POST' });
      if (res?.data) {
        setScanResult(res.data);
      } else if (res?.os) {
        setScanResult(res);
      }
    } catch (err: any) {
      setScanResult({ error: err.message || 'Scan failed' });
    } finally {
      setIsScanning(false);
    }
  };

  const handleIsolateHost = async (agentId: string, isolate: boolean) => {
    setActionInProgress(true);
    setActionMsg(null);
    try {
      const res = await fetchApi('/api/v1/endpoint/actions/isolate', {
        method: 'POST',
        body: JSON.stringify({ agent_id: agentId, isolate }),
      });
      if (res?.success) {
        setActionMsg({
          type: 'success',
          text: isolate
            ? (lang === 'ar' ? 'تم إصدار أمر العزل الشبكي الفوري للجهاز' : 'Isolation command queued successfully')
            : (lang === 'ar' ? 'تم إلغاء عزل الجهاز' : 'Unisolate command queued successfully'),
        });
        loadData();
      } else {
        setActionMsg({
          type: 'error',
          text: res?.error?.message || (lang === 'ar' ? 'فشل تنفيذ أمر العزل' : 'Failed to queue isolation action'),
        });
      }
    } catch (err: any) {
      setActionMsg({ type: 'error', text: err.message });
    } finally {
      setActionInProgress(false);
    }
  };

  const handleKillProcess = async (agentId: string) => {
    if (!killPid.trim()) return;
    setActionInProgress(true);
    setActionMsg(null);
    try {
      const res = await fetchApi('/api/v1/endpoint/actions/kill-process', {
        method: 'POST',
        body: JSON.stringify({ agent_id: agentId, pid: parseInt(killPid.trim(), 10) }),
      });
      if (res?.success) {
        setActionMsg({
          type: 'success',
          text: lang === 'ar' ? `تم إصدار أمر إنهاء العملية (PID: ${killPid}) عن بعد` : `Kill process command queued for PID ${killPid}`,
        });
        setKillPid('');
      } else {
        setActionMsg({
          type: 'error',
          text: res?.error?.message || (lang === 'ar' ? 'فشل إنهاء العملية' : 'Failed to kill process'),
        });
      }
    } catch (err: any) {
      setActionMsg({ type: 'error', text: err.message });
    } finally {
      setActionInProgress(false);
    }
  };

  const filteredAgents = agents.filter((agent) => {
    const matchesSearch =
      agent.hostname.toLowerCase().includes(searchQuery.toLowerCase()) ||
      agent.agent_id.toLowerCase().includes(searchQuery.toLowerCase()) ||
      agent.ip_addresses?.some((ip) => ip.includes(searchQuery));
    const matchesState = stateFilter === 'all' || agent.state === stateFilter;
    return matchesSearch && matchesState;
  });

  const getSeverityBadge = (sev: string) => {
    const s = sev.toLowerCase();
    if (s === 'critical') return 'bg-red-500/20 text-red-400 border-red-500/30';
    if (s === 'high') return 'bg-orange-500/20 text-orange-400 border-orange-500/30';
    if (s === 'medium') return 'bg-amber-500/20 text-amber-400 border-amber-500/30';
    if (s === 'low') return 'bg-blue-500/20 text-blue-400 border-blue-500/30';
    return 'bg-muted text-muted-foreground border-border/40';
  };

  const getStateBadge = (state: string) => {
    if (state === 'online') return { color: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/25', label: lang === 'ar' ? 'متصل' : 'Online' };
    if (state === 'isolated') return { color: 'text-red-400 bg-red-500/10 border-red-500/30', label: lang === 'ar' ? 'معزول' : 'Isolated' };
    if (state === 'degraded') return { color: 'text-amber-400 bg-amber-500/10 border-amber-500/30', label: lang === 'ar' ? 'غير مستقر' : 'Degraded' };
    return { color: 'text-muted-foreground bg-muted/20 border-border/40', label: lang === 'ar' ? 'غير متصل' : 'Offline' };
  };

  return (
    <div className="flex-1 space-y-6 p-6">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-border/60 pb-5">
        <div>
          <h1 className="text-2xl font-black tracking-tight text-foreground flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-amber-500/10 border border-amber-500/25 text-amber-400">
              <ShieldCheck className="h-6 w-6" />
            </div>
            <span>EndpointScope — {lang === 'ar' ? 'مراقبة واستجابة نقاط النهاية (EDR)' : 'Endpoint Detection & Response'}</span>
          </h1>
          <p className="text-xs text-muted-foreground mt-1">
            {lang === 'ar'
              ? 'مراقبة مستمرة لنقاط النهاية، كشف التهديدات الفوري، واستجابة عزل الأجهزة المشبوهة محلياً'
              : 'Real-time endpoint telemetry, process heuristic analysis, and immediate network host containment'}
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={handleTriggerHostScan}
            className="inline-flex items-center gap-2 rounded-xl bg-amber-500/15 border border-amber-500/30 px-3.5 py-2 text-xs font-semibold text-amber-300 hover:bg-amber-500/25 transition-all shadow-sm"
          >
            <Radio className="h-4 w-4" />
            {lang === 'ar' ? 'فحص النظام المباشر' : 'Live Host Scan'}
          </button>
          <button
            onClick={loadData}
            disabled={loading}
            className="inline-flex items-center gap-2 rounded-xl border border-border/60 bg-muted/20 px-3 py-2 text-xs font-medium text-foreground hover:bg-muted/40 transition-colors"
          >
            <RotateCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
            {lang === 'ar' ? 'تحديث' : 'Refresh'}
          </button>
        </div>
      </div>

      {/* Feature Gate Banner (if Community edition) */}
      {currentEdition.toLowerCase() === 'community' && (
        <div className="rounded-2xl border border-amber-500/30 bg-gradient-to-r from-amber-500/10 via-orange-500/5 to-transparent p-4 flex flex-col sm:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-amber-500/20 text-amber-400 shrink-0">
              <Sparkles className="h-5 w-5" />
            </div>
            <div>
              <h4 className="text-sm font-bold text-foreground flex items-center gap-2">
                {lang === 'ar' ? 'طبعة Community: مراقبة تجريبية لنقاط النهاية' : 'Community Edition: Evaluation EDR Mode'}
                <span className="text-[10px] uppercase font-mono px-2 py-0.5 rounded bg-amber-500/20 text-amber-300 border border-amber-500/30">
                  {lang === 'ar' ? 'محدود بـ 5 أجهزة' : 'Max 5 Agents'}
                </span>
              </h4>
              <p className="text-xs text-muted-foreground mt-0.5">
                {lang === 'ar'
                  ? 'قم بالترقية إلى طبعة Professional أو Enterprise لإلغاء حدود الأجهزة وتفعيل الاستجابة الآلية وعزل التهديدات على مستوى المؤسسة.'
                  : 'Upgrade to Professional or Enterprise for 500+ agents, automated heuristic isolation, and sovereign threat hunting.'}
              </p>
            </div>
          </div>
          <button
            onClick={() => setUpgradeModalOpen(true)}
            className="inline-flex items-center gap-2 rounded-xl bg-gradient-to-r from-amber-500 to-orange-500 px-4 py-2 text-xs font-bold text-white shadow hover:opacity-95 transition-opacity whitespace-nowrap"
          >
            <Sparkles className="h-4 w-4" />
            {lang === 'ar' ? 'استعراض باقات الترقية' : 'View Upgrade Options'}
          </button>
        </div>
      )}

      {/* Top Stats Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Total Agents */}
        <div className="rounded-xl border border-border/80 bg-card p-4 shadow-sm flex items-center justify-between">
          <div>
            <span className="text-xs font-medium text-muted-foreground">
              {lang === 'ar' ? 'إجمالي أجهزة النهاية' : 'Total Endpoints'}
            </span>
            <div className="text-2xl font-black text-foreground mt-1">
              {stats?.total_agents || agents.length || 0}
            </div>
            <span className="text-[11px] text-muted-foreground mt-0.5 block">
              {stats?.agents?.online || agents.filter((a) => a.state === 'online').length || 0} {lang === 'ar' ? 'متصل الآن' : 'online now'}
            </span>
          </div>
          <div className="flex h-12 w-12 items-center justify-center rounded-2xl bg-blue-500/10 border border-blue-500/20 text-blue-400">
            <Server className="h-6 w-6" />
          </div>
        </div>

        {/* Critical Alerts */}
        <div className="rounded-xl border border-border/80 bg-card p-4 shadow-sm flex items-center justify-between">
          <div>
            <span className="text-xs font-medium text-muted-foreground">
              {lang === 'ar' ? 'إنذارات حرجة (24 ساعة)' : 'Critical Alerts (24h)'}
            </span>
            <div className="text-2xl font-black text-red-400 mt-1">
              {stats?.critical_events_24h || 0}
            </div>
            <span className="text-[11px] text-muted-foreground mt-0.5 block">
              {lang === 'ar' ? 'تتطلب تدخلاً فورياً' : 'Requires immediate action'}
            </span>
          </div>
          <div className="flex h-12 w-12 items-center justify-center rounded-2xl bg-red-500/10 border border-red-500/20 text-red-400">
            <AlertTriangle className="h-6 w-6" />
          </div>
        </div>

        {/* Isolated Hosts */}
        <div className="rounded-xl border border-border/80 bg-card p-4 shadow-sm flex items-center justify-between">
          <div>
            <span className="text-xs font-medium text-muted-foreground">
              {lang === 'ar' ? 'الأجهزة المعزولة' : 'Isolated Hosts'}
            </span>
            <div className="text-2xl font-black text-amber-400 mt-1">
              {agents.filter((a) => a.state === 'isolated').length || 0}
            </div>
            <span className="text-[11px] text-muted-foreground mt-0.5 block">
              {lang === 'ar' ? 'معزولة عن الشبكة لمنع الانتشار' : 'Contained from network'}
            </span>
          </div>
          <div className="flex h-12 w-12 items-center justify-center rounded-2xl bg-amber-500/10 border border-amber-500/20 text-amber-400">
            <Lock className="h-6 w-6" />
          </div>
        </div>

        {/* Total Events */}
        <div className="rounded-xl border border-border/80 bg-card p-4 shadow-sm flex items-center justify-between">
          <div>
            <span className="text-xs font-medium text-muted-foreground">
              {lang === 'ar' ? 'أحداث العمليات المجمعة' : 'Telemetry Events Ingested'}
            </span>
            <div className="text-2xl font-black text-emerald-400 mt-1">
              {stats?.total_events?.toLocaleString() || '0'}
            </div>
            <span className="text-[11px] text-muted-foreground mt-0.5 block">
              {lang === 'ar' ? 'معالجة ومفهرسة محلياً' : 'Indexed locally in SQLite'}
            </span>
          </div>
          <div className="flex h-12 w-12 items-center justify-center rounded-2xl bg-emerald-500/10 border border-emerald-500/20 text-emerald-400">
            <Activity className="h-6 w-6" />
          </div>
        </div>
      </div>

      {/* Agents Table Section */}
      <div className="rounded-2xl border border-border/80 bg-card shadow-sm overflow-hidden">
        {/* Table Filters Header */}
        <div className="p-4 border-b border-border/60 flex flex-col sm:flex-row items-center justify-between gap-3 bg-muted/10">
          <div className="relative w-full sm:w-80">
            <Search className="absolute right-3 top-2.5 h-4 w-4 text-muted-foreground" />
            <input
              type="text"
              placeholder={lang === 'ar' ? 'بحث بالاسم، المعرف، أو عنوان IP...' : 'Search by hostname, ID, or IP...'}
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full rounded-xl border border-border/80 bg-background/80 py-2 pr-9 pl-4 text-xs text-foreground focus:outline-none focus:ring-2 focus:ring-primary/40"
            />
          </div>

          <div className="flex items-center gap-2 w-full sm:w-auto">
            <span className="text-xs text-muted-foreground whitespace-nowrap">{lang === 'ar' ? 'الحالة:' : 'Status:'}</span>
            <select
              value={stateFilter}
              onChange={(e) => setStateFilter(e.target.value)}
              className="rounded-xl border border-border/80 bg-background/80 px-3 py-1.5 text-xs text-foreground focus:outline-none focus:ring-2 focus:ring-primary/40"
            >
              <option value="all">{lang === 'ar' ? 'جميع الأجهزة' : 'All States'}</option>
              <option value="online">{lang === 'ar' ? 'متصل (Online)' : 'Online'}</option>
              <option value="offline">{lang === 'ar' ? 'غير متصل (Offline)' : 'Offline'}</option>
              <option value="isolated">{lang === 'ar' ? 'معزول (Isolated)' : 'Isolated'}</option>
            </select>
          </div>
        </div>

        {/* Table Content */}
        <div className="overflow-x-auto">
          <table className="w-full text-start text-xs">
            <thead className="bg-muted/30 border-b border-border/60 text-muted-foreground uppercase tracking-wider font-semibold">
              <tr>
                <th className="px-4 py-3 text-start">{lang === 'ar' ? 'اسم الجهاز (Hostname)' : 'Hostname'}</th>
                <th className="px-4 py-3 text-start">{lang === 'ar' ? 'نظام التشغيل' : 'OS & Version'}</th>
                <th className="px-4 py-3 text-start">{lang === 'ar' ? 'عنوان IP / MAC' : 'IP / MAC'}</th>
                <th className="px-4 py-3 text-start">{lang === 'ar' ? 'حالة الوكيل' : 'Agent State'}</th>
                <th className="px-4 py-3 text-start">{lang === 'ar' ? 'آخر نبضة (Heartbeat)' : 'Last Heartbeat'}</th>
                <th className="px-4 py-3 text-start">{lang === 'ar' ? 'تقييم المخاطر' : 'Risk Score'}</th>
                <th className="px-4 py-3 text-end">{lang === 'ar' ? 'الإجراءات' : 'Actions'}</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border/40">
              {loading ? (
                <tr>
                  <td colSpan={7} className="px-4 py-8 text-center text-muted-foreground">
                    <div className="flex items-center justify-center gap-2">
                      <div className="h-4 w-4 animate-spin rounded-full border-2 border-primary border-t-transparent" />
                      <span>{lang === 'ar' ? 'جاري تحميل وكلاء نقاط النهاية...' : 'Loading endpoint agents...'}</span>
                    </div>
                  </td>
                </tr>
              ) : filteredAgents.length === 0 ? (
                <tr>
                  <td colSpan={7} className="px-4 py-12 text-center text-muted-foreground">
                    <Server className="h-8 w-8 mx-auto text-muted-foreground/40 mb-2" />
                    <p className="font-semibold text-foreground/80">
                      {lang === 'ar' ? 'لم يتم العثور على أجهزة مسجلة' : 'No registered endpoints found'}
                    </p>
                    <p className="text-xs text-muted-foreground mt-1">
                      {lang === 'ar'
                        ? 'يمكنك إجراء فحص مباشر للمضيف الحالي أو تسجيل وكلاء إضافيين عبر API.'
                        : 'Run a live host scan or register agents via REST API.'}
                    </p>
                    <button
                      onClick={handleTriggerHostScan}
                      className="mt-4 inline-flex items-center gap-2 rounded-xl bg-primary px-3.5 py-1.5 text-xs font-bold text-primary-foreground shadow"
                    >
                      <Radio className="h-4 w-4" />
                      {lang === 'ar' ? 'فحص هذا الجهاز الآن' : 'Scan This Machine Now'}
                    </button>
                  </td>
                </tr>
              ) : (
                filteredAgents.map((agent) => {
                  const stateBadge = getStateBadge(agent.state);
                  return (
                    <tr key={agent.agent_id} className="hover:bg-muted/20 transition-colors">
                      <td className="px-4 py-3 font-semibold text-foreground">
                        <div className="flex items-center gap-2">
                          <Server className="h-4 w-4 text-muted-foreground" />
                          <div>
                            <div>{agent.hostname}</div>
                            <div className="text-[10px] font-mono text-muted-foreground">{agent.agent_id}</div>
                          </div>
                        </div>
                      </td>
                      <td className="px-4 py-3 text-foreground/90">
                        <div className="capitalize">{agent.os_type}</div>
                        <div className="text-[10px] text-muted-foreground">{agent.os_version || 'v1.0.0'}</div>
                      </td>
                      <td className="px-4 py-3 font-mono text-foreground/90">
                        <div>{agent.ip_addresses?.[0] || '127.0.0.1'}</div>
                        <div className="text-[10px] text-muted-foreground">{agent.mac_addresses?.[0] || '—'}</div>
                      </td>
                      <td className="px-4 py-3">
                        <span className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-[11px] font-semibold border ${stateBadge.color}`}>
                          {stateBadge.label}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-muted-foreground font-mono text-[11px]">
                        {agent.last_heartbeat ? new Date(agent.last_heartbeat).toLocaleTimeString() : '—'}
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2">
                          <div className="w-16 h-2 rounded-full bg-muted overflow-hidden">
                            <div
                              className={`h-full rounded-full ${
                                agent.risk_score > 70
                                  ? 'bg-red-500'
                                  : agent.risk_score > 30
                                  ? 'bg-amber-500'
                                  : 'bg-emerald-500'
                              }`}
                              style={{ width: `${Math.min(100, agent.risk_score || 10)}%` }}
                            />
                          </div>
                          <span className="font-mono text-xs font-semibold">{agent.risk_score || 0}</span>
                        </div>
                      </td>
                      <td className="px-4 py-3 text-end">
                        <div className="flex items-center justify-end gap-1.5">
                          <button
                            onClick={() => openAgentDetails(agent)}
                            className="p-1.5 rounded-lg border border-border/60 hover:bg-muted text-foreground transition-colors"
                            title={lang === 'ar' ? 'عرض الأحداث والتفاصيل' : 'View Events'}
                          >
                            <Eye className="h-4 w-4" />
                          </button>
                          {agent.state === 'isolated' ? (
                            <button
                              onClick={() => handleIsolateHost(agent.agent_id, false)}
                              className="p-1.5 rounded-lg border border-emerald-500/30 bg-emerald-500/10 text-emerald-400 hover:bg-emerald-500/20 transition-colors"
                              title={lang === 'ar' ? 'إلغاء العزل' : 'Unisolate'}
                            >
                              <Unlock className="h-4 w-4" />
                            </button>
                          ) : (
                            <button
                              onClick={() => handleIsolateHost(agent.agent_id, true)}
                              className="p-1.5 rounded-lg border border-red-500/30 bg-red-500/10 text-red-400 hover:bg-red-500/20 transition-colors"
                              title={lang === 'ar' ? 'عزل فوري عن الشبكة' : 'Isolate Host'}
                            >
                              <Lock className="h-4 w-4" />
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Agent Detailed Inspection Modal */}
      {selectedAgent && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4 animate-in fade-in duration-150">
          <div className="relative w-full max-w-4xl max-h-[85vh] overflow-hidden rounded-2xl border border-border/80 bg-card shadow-2xl flex flex-col">
            {/* Modal Header */}
            <div className="flex items-center justify-between border-b border-border/60 px-6 py-4 bg-muted/20">
              <div className="flex items-center gap-3">
                <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-amber-500/10 text-amber-400 border border-amber-500/20">
                  <Server className="h-5 w-5" />
                </div>
                <div>
                  <h3 className="text-lg font-bold text-foreground flex items-center gap-2">
                    <span>{selectedAgent.hostname}</span>
                    <span className="text-xs font-mono text-muted-foreground">({selectedAgent.agent_id})</span>
                  </h3>
                  <p className="text-xs text-muted-foreground">
                    {selectedAgent.os_type} • IP: {selectedAgent.ip_addresses?.join(', ') || '127.0.0.1'}
                  </p>
                </div>
              </div>
              <button
                onClick={() => setSelectedAgent(null)}
                className="rounded-lg p-2 text-muted-foreground hover:bg-muted/40 hover:text-foreground"
              >
                <X className="h-5 w-5" />
              </button>
            </div>

            {/* Modal Body */}
            <div className="flex-1 overflow-y-auto p-6 space-y-6">
              {/* Action Banner Message */}
              {actionMsg && (
                <div className={`p-3 rounded-xl text-xs font-medium border ${
                  actionMsg.type === 'success'
                    ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400'
                    : 'bg-red-500/10 border-red-500/30 text-red-400'
                }`}>
                  {actionMsg.text}
                </div>
              )}

              {/* Response Actions Control Panel */}
              <div className="rounded-xl border border-border/80 bg-muted/20 p-4 space-y-3">
                <h4 className="text-xs font-bold uppercase tracking-wider text-foreground flex items-center gap-2">
                  <ShieldAlert className="h-4 w-4 text-red-400" />
                  <span>{lang === 'ar' ? 'إجراءات الاستجابة الفورية عن بعد (Remote Response Actions)' : 'Remote Response Actions'}</span>
                </h4>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-1">
                  {/* Isolation Control */}
                  <div className="flex items-center justify-between p-3 rounded-xl border border-border/60 bg-background/60">
                    <div>
                      <div className="text-xs font-semibold text-foreground">{lang === 'ar' ? 'العزل الشبكي' : 'Network Isolation'}</div>
                      <div className="text-[11px] text-muted-foreground">{lang === 'ar' ? 'قطع كل الاتصالات باستثناء خادم التحليل' : 'Cut all network traffic except platform'}</div>
                    </div>
                    {selectedAgent.state === 'isolated' ? (
                      <button
                        onClick={() => handleIsolateHost(selectedAgent.agent_id, false)}
                        disabled={actionInProgress}
                        className="rounded-lg bg-emerald-500/20 border border-emerald-500/30 px-3 py-1.5 text-xs font-bold text-emerald-400 hover:bg-emerald-500/30"
                      >
                        {lang === 'ar' ? 'إلغاء العزل' : 'Unisolate'}
                      </button>
                    ) : (
                      <button
                        onClick={() => handleIsolateHost(selectedAgent.agent_id, true)}
                        disabled={actionInProgress}
                        className="rounded-lg bg-red-500/20 border border-red-500/30 px-3 py-1.5 text-xs font-bold text-red-400 hover:bg-red-500/30"
                      >
                        {lang === 'ar' ? 'عزل فوري' : 'Isolate'}
                      </button>
                    )}
                  </div>

                  {/* Kill Process Form */}
                  <div className="flex items-center gap-2 p-3 rounded-xl border border-border/60 bg-background/60">
                    <input
                      type="number"
                      placeholder="PID (e.g. 4812)"
                      value={killPid}
                      onChange={(e) => setKillPid(e.target.value)}
                      className="w-28 rounded-lg border border-border/80 bg-muted/40 px-2.5 py-1.5 text-xs font-mono text-foreground focus:outline-none"
                    />
                    <button
                      onClick={() => handleKillProcess(selectedAgent.agent_id)}
                      disabled={actionInProgress || !killPid}
                      className="flex-1 rounded-lg bg-red-500/20 border border-red-500/30 py-1.5 text-xs font-bold text-red-400 hover:bg-red-500/30 disabled:opacity-50"
                    >
                      {lang === 'ar' ? 'إنهاء العملية' : 'Kill PID'}
                    </button>
                  </div>
                </div>
              </div>

              {/* Recent Events Stream */}
              <div className="space-y-3">
                <h4 className="text-xs font-bold uppercase tracking-wider text-muted-foreground flex items-center gap-2">
                  <Activity className="h-4 w-4" />
                  <span>{lang === 'ar' ? 'سجل الأحداث والعمليات الأخيرة للوكيل' : 'Recent Telemetry & Process Events'}</span>
                </h4>
                {loadingEvents ? (
                  <div className="p-8 text-center text-xs text-muted-foreground">
                    <div className="h-4 w-4 animate-spin rounded-full border-2 border-primary border-t-transparent mx-auto mb-2" />
                    <span>{lang === 'ar' ? 'جاري تحميل أحداث الوكيل...' : 'Loading events...'}</span>
                  </div>
                ) : agentEvents.length === 0 ? (
                  <div className="p-6 rounded-xl border border-border/60 text-center text-xs text-muted-foreground">
                    {lang === 'ar' ? 'لا توجد أحداث مسجلة حديثاً لهذا الجهاز' : 'No recent events recorded for this agent'}
                  </div>
                ) : (
                  <div className="space-y-2 max-h-72 overflow-y-auto">
                    {agentEvents.map((evt) => (
                      <div
                        key={evt.event_id}
                        className="rounded-xl border border-border/60 bg-background/60 p-3 text-xs space-y-1 hover:border-primary/30 transition-colors"
                      >
                        <div className="flex items-center justify-between">
                          <span className="font-semibold text-foreground flex items-center gap-2">
                            <span className="font-mono text-primary uppercase text-[11px]">{evt.event_type}</span>
                            {evt.process_name && <span className="font-mono text-muted-foreground">({evt.process_name})</span>}
                          </span>
                          <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold border uppercase ${getSeverityBadge(evt.severity)}`}>
                            {evt.severity}
                          </span>
                        </div>
                        {evt.command_line && (
                          <div className="font-mono text-[11px] text-foreground/80 bg-muted/30 p-1.5 rounded-lg break-all">
                            {evt.command_line}
                          </div>
                        )}
                        <div className="text-[10px] text-muted-foreground font-mono">
                          {new Date(evt.timestamp).toLocaleString()}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Host Live Scan Results Modal */}
      {scanModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4 animate-in fade-in duration-150">
          <div className="relative w-full max-w-3xl max-h-[80vh] overflow-hidden rounded-2xl border border-border/80 bg-card shadow-2xl flex flex-col">
            <div className="flex items-center justify-between border-b border-border/60 px-6 py-4 bg-muted/20">
              <div className="flex items-center gap-2.5">
                <Radio className="h-5 w-5 text-amber-400 animate-pulse" />
                <h3 className="text-base font-bold text-foreground">
                  {lang === 'ar' ? 'نتائج فحص النظام المباشر للمضيف (Live System Snapshot)' : 'Live Host System Snapshot'}
                </h3>
              </div>
              <button
                onClick={() => setScanModalOpen(false)}
                className="rounded-lg p-2 text-muted-foreground hover:bg-muted/40 hover:text-foreground"
              >
                <X className="h-5 w-5" />
              </button>
            </div>

            <div className="flex-1 overflow-y-auto p-6 space-y-4">
              {isScanning ? (
                <div className="py-16 text-center space-y-3">
                  <div className="h-8 w-8 animate-spin rounded-full border-2 border-amber-400 border-t-transparent mx-auto" />
                  <p className="text-sm font-semibold text-foreground">
                    {lang === 'ar' ? 'جاري فحص العمليات النشطة، منافذ الاستماع، واتصالات الشبكة...' : 'Scanning active processes, listening ports, and connections...'}
                  </p>
                  <p className="text-xs text-muted-foreground">
                    {lang === 'ar' ? 'يتم الفحص محلياً بأقل استهلاك لموارد المعالج (< 5% CPU)' : 'Zero performance overhead inspection'}
                  </p>
                </div>
              ) : scanResult ? (
                <div className="space-y-4">
                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                    <div className="rounded-xl border border-border/60 bg-muted/20 p-3 text-xs">
                      <span className="text-muted-foreground block">{lang === 'ar' ? 'العمليات النشطة المفحوصة' : 'Processes Inspected'}</span>
                      <span className="text-xl font-bold text-foreground mt-1 block">
                        {scanResult.processes?.length || 0}
                      </span>
                    </div>
                    <div className="rounded-xl border border-border/60 bg-muted/20 p-3 text-xs">
                      <span className="text-muted-foreground block">{lang === 'ar' ? 'الاتصالات النشطة' : 'Active Connections'}</span>
                      <span className="text-xl font-bold text-foreground mt-1 block">
                        {scanResult.connections?.length || 0}
                      </span>
                    </div>
                    <div className="rounded-xl border border-border/60 bg-muted/20 p-3 text-xs">
                      <span className="text-muted-foreground block">{lang === 'ar' ? 'منافذ الاستماع المفتوحة' : 'Listening Ports'}</span>
                      <span className="text-xl font-bold text-foreground mt-1 block">
                        {scanResult.listening_ports?.length || 0}
                      </span>
                    </div>
                  </div>

                  {/* Processes Preview */}
                  {scanResult.processes && scanResult.processes.length > 0 && (
                    <div className="space-y-2">
                      <h4 className="text-xs font-bold uppercase tracking-wider text-muted-foreground">
                        {lang === 'ar' ? 'عينة من العمليات النشطة' : 'Active Processes Sample'}
                      </h4>
                      <div className="max-h-56 overflow-y-auto rounded-xl border border-border/60 divide-y divide-border/40">
                        {scanResult.processes.slice(0, 20).map((p: any, idx: number) => (
                          <div key={idx} className="p-2.5 flex items-center justify-between text-xs hover:bg-muted/20">
                            <div className="flex items-center gap-2">
                              <Terminal className="h-3.5 w-3.5 text-muted-foreground" />
                              <span className="font-mono font-semibold text-foreground">{p.name}</span>
                              <span className="text-[10px] text-muted-foreground font-mono">PID: {p.pid}</span>
                            </div>
                            <span className="text-[10px] text-muted-foreground truncate max-w-xs">{p.cmdline || p.path || ''}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              ) : (
                <div className="text-center py-8 text-xs text-muted-foreground">
                  {lang === 'ar' ? 'لم تتوفر نتائج فحص' : 'No scan results'}
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Upgrade Modal */}
      <EditionUpgradeModal
        isOpen={upgradeModalOpen}
        onClose={() => setUpgradeModalOpen(false)}
      />
    </div>
  );
}
