'use client';

import React, { useState, useEffect } from 'react';
import { Navbar } from '../../components/Navbar';
import { GraphCanvas } from '../../components/correlation/GraphCanvas';
import { GraphEntityDrawer } from '../../components/correlation/GraphEntityDrawer';
import { AttackChainsList } from '../../components/correlation/AttackChainsList';
import { LateralMovementsList } from '../../components/correlation/LateralMovementsList';
import { InsiderThreatsList } from '../../components/correlation/InsiderThreatsList';
import {
  getCorrelationSummary,
  getCorrelationGraph,
  getAttackChains,
  getLateralMovements,
  getInsiderThreats,
  promoteGraphPatternToIncident,
  runCorrelationAnalysis,
} from '../../lib/api';
import {
  GraphSnapshot,
  GraphNode,
  CorrelationSummary,
  AttackChain,
  LateralMovement,
  InsiderThreat,
} from '../../lib/types';
import {
  Network,
  Share2,
  ShieldAlert,
  Activity,
  Layers,
  RefreshCw,
  AlertTriangle,
  Zap,
} from 'lucide-react';

export default function CorrelationPage() {
  const [activeTab, setActiveTab] = useState<'graph' | 'chains' | 'laterals' | 'insiders'>('graph');
  const [loading, setLoading] = useState(true);
  const [analyzing, setAnalyzing] = useState(false);
  const [summary, setSummary] = useState<CorrelationSummary | null>(null);
  const [graphData, setGraphData] = useState<GraphSnapshot>({ nodes: [], edges: [], total_nodes: 0, total_edges: 0 });
  const [chains, setChains] = useState<AttackChain[]>([]);
  const [laterals, setLaterals] = useState<LateralMovement[]>([]);
  const [insiders, setInsiders] = useState<InsiderThreat[]>([]);
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [notification, setNotification] = useState<{ type: 'success' | 'error'; message: string } | null>(null);

  const showNotification = (type: 'success' | 'error', message: string) => {
    setNotification({ type, message });
    setTimeout(() => setNotification(null), 4000);
  };

  const loadAll = async () => {
    setLoading(true);
    try {
      const [sumRes, graphRes, chainsRes, latRes, insRes] = await Promise.all([
        getCorrelationSummary(),
        getCorrelationGraph(),
        getAttackChains(),
        getLateralMovements(),
        getInsiderThreats(),
      ]);
      setSummary(sumRes);
      setGraphData(graphRes);
      setChains(chainsRes.attack_chains || []);
      setLaterals(latRes.lateral_movements || []);
      setInsiders(insRes.insider_threats || []);
    } catch (err: any) {
      console.error('Failed to load correlation data:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadAll();
  }, []);

  const handleRunAnalysis = async () => {
    setAnalyzing(true);
    try {
      await runCorrelationAnalysis();
      showNotification('success', 'تم إعادة تحليل وتحديث الرسم البياني الجنائي بنجاح.');
      await loadAll();
    } catch (err: any) {
      showNotification('error', 'تعذر استكمال تحليل الترابط الجنائي: ' + err.message);
    } finally {
      setAnalyzing(false);
    }
  };

  const handlePromote = async (patternType: 'attack_chain' | 'lateral_movement', patternId: string) => {
    try {
      const res = await promoteGraphPatternToIncident(patternType, patternId);
      if (res.success) {
        showNotification('success', 'تم ترقية نمط الترابط وإنشاء حادث أمني رسمي بنجاح.');
        await loadAll();
      }
    } catch (err: any) {
      showNotification('error', err.message || 'فشلت ترقية النمط.');
    }
  };

  const handleViewInGraph = (chain: AttackChain) => {
    setActiveTab('graph');
    if (chain.nodes && chain.nodes.length > 0) {
      setSelectedNode(chain.nodes[0] as unknown as GraphNode);
    }
  };

  return (
    <div className="min-h-screen bg-dark-950 text-slate-100 flex flex-col font-sans selection:bg-primary/30">
      <Navbar />

      <main className="flex-1 w-full max-w-[1600px] mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-6">
        {/* Notification Toast */}
        {notification && (
          <div
            className={`fixed bottom-6 left-6 z-50 px-4 py-3 rounded-xl border shadow-2xl flex items-center gap-2 text-xs font-bold animate-in fade-in slide-in-from-bottom-3 duration-200 ${
              notification.type === 'success'
                ? 'bg-emerald-950/90 border-emerald-500/40 text-emerald-200'
                : 'bg-red-950/90 border-red-500/40 text-red-200'
            }`}
          >
            {notification.type === 'success' ? <Zap className="w-4 h-4 text-emerald-400" /> : <AlertTriangle className="w-4 h-4 text-red-400" />}
            <span>{notification.message}</span>
          </div>
        )}

        {/* Header Section */}
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-white/10 pb-5">
          <div className="flex items-center gap-3">
            <div className="w-12 h-12 rounded-2xl bg-gradient-to-br from-purple-500/20 to-primary/20 border border-purple-500/30 flex items-center justify-center text-purple-400 shadow-lg shadow-purple-500/10">
              <Network className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-xl sm:text-2xl font-bold font-heading text-white">
                  الترابط الجنائي وسلاسل الهجوم (Graph Correlation)
                </h1>
                <span className="px-2 py-0.5 rounded-md text-[10px] font-mono font-bold bg-purple-500/10 border border-purple-500/25 text-purple-400">
                  Enterprise Graph Layer
                </span>
              </div>
              <p className="text-xs sm:text-sm text-slate-400 mt-0.5">
                رسم بياني طوبولوجي لتحليل مسارات الهجوم متعددة المراحل، التنقل الأفقي، والتهديدات الداخلية.
              </p>
            </div>
          </div>

          {/* Actions */}
          <div className="flex items-center gap-2">
            <button
              onClick={handleRunAnalysis}
              disabled={analyzing}
              className="flex items-center gap-2 px-3.5 py-2 rounded-xl bg-primary/20 hover:bg-primary/30 border border-primary/40 text-xs font-bold text-primary transition-all shadow-sm shadow-primary/10 disabled:opacity-50"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${analyzing ? 'animate-spin' : ''}`} />
              <span>{analyzing ? 'جاري التحليل...' : 'تحديث وتحليل الرسم البياني'}</span>
            </button>
          </div>
        </div>

        {/* 4 KPI Cards */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          <div className="p-4 rounded-2xl bg-dark-900/60 border border-white/10 shadow-sm flex items-center justify-between">
            <div>
              <span className="text-xs text-slate-400 block mb-1">إجمالي الكيانات (Nodes)</span>
              <span className="text-2xl font-bold font-mono text-white">
                {summary ? summary.total_nodes : graphData.total_nodes}
              </span>
              <span className="text-[10px] text-slate-500 block mt-0.5">
                {summary ? summary.total_edges : graphData.total_edges} علاقة مسجلة
              </span>
            </div>
            <div className="w-10 h-10 rounded-xl bg-blue-500/10 border border-blue-500/30 flex items-center justify-center text-blue-400">
              <Share2 className="w-5 h-5" />
            </div>
          </div>

          <div className="p-4 rounded-2xl bg-dark-900/60 border border-white/10 shadow-sm flex items-center justify-between">
            <div>
              <span className="text-xs text-slate-400 block mb-1">سلاسل الهجوم (Attack Chains)</span>
              <span className="text-2xl font-bold font-mono text-red-400">
                {chains.length}
              </span>
              <span className="text-[10px] text-slate-500 block mt-0.5">مسارات هجوم متعددة المراحل</span>
            </div>
            <div className="w-10 h-10 rounded-xl bg-red-500/10 border border-red-500/30 flex items-center justify-center text-red-400">
              <ShieldAlert className="w-5 h-5" />
            </div>
          </div>

          <div className="p-4 rounded-2xl bg-dark-900/60 border border-white/10 shadow-sm flex items-center justify-between">
            <div>
              <span className="text-xs text-slate-400 block mb-1">حركات التنقل الأفقي (Lateral)</span>
              <span className="text-2xl font-bold font-mono text-amber-400">
                {laterals.length}
              </span>
              <span className="text-[10px] text-slate-500 block mt-0.5">قفزات بين محطات داخلية</span>
            </div>
            <div className="w-10 h-10 rounded-xl bg-amber-500/10 border border-amber-500/30 flex items-center justify-center text-amber-400">
              <Network className="w-5 h-5" />
            </div>
          </div>

          <div className="p-4 rounded-2xl bg-dark-900/60 border border-white/10 shadow-sm flex items-center justify-between">
            <div>
              <span className="text-xs text-slate-400 block mb-1">التهديدات الداخلية (Insider)</span>
              <span className="text-2xl font-bold font-mono text-purple-400">
                {insiders.length}
              </span>
              <span className="text-[10px] text-slate-500 block mt-0.5">أنشطة مستخدمين شاذة</span>
            </div>
            <div className="w-10 h-10 rounded-xl bg-purple-500/10 border border-purple-500/30 flex items-center justify-center text-purple-400">
              <Activity className="w-5 h-5" />
            </div>
          </div>
        </div>

        {/* Navigation Tabs */}
        <div className="flex items-center gap-2 border-b border-white/10 pb-2">
          <button
            onClick={() => setActiveTab('graph')}
            className={`flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-bold transition-all ${
              activeTab === 'graph'
                ? 'bg-primary/20 text-primary border border-primary/30 shadow-sm shadow-primary/10'
                : 'text-slate-400 hover:text-white hover:bg-white/5'
            }`}
          >
            <Layers className="w-4 h-4" />
            <span>مستكشف الرسم البياني (Graph Topology)</span>
          </button>

          <button
            onClick={() => setActiveTab('chains')}
            className={`flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-bold transition-all ${
              activeTab === 'chains'
                ? 'bg-red-500/20 text-red-400 border border-red-500/30 shadow-sm shadow-red-500/10'
                : 'text-slate-400 hover:text-white hover:bg-white/5'
            }`}
          >
            <ShieldAlert className="w-4 h-4" />
            <span>سلاسل الهجوم ({chains.length})</span>
          </button>

          <button
            onClick={() => setActiveTab('laterals')}
            className={`flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-bold transition-all ${
              activeTab === 'laterals'
                ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30 shadow-sm shadow-amber-500/10'
                : 'text-slate-400 hover:text-white hover:bg-white/5'
            }`}
          >
            <Network className="w-4 h-4" />
            <span>التنقل الأفقي ({laterals.length})</span>
          </button>

          <button
            onClick={() => setActiveTab('insiders')}
            className={`flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-bold transition-all ${
              activeTab === 'insiders'
                ? 'bg-purple-500/20 text-purple-400 border border-purple-500/30 shadow-sm shadow-purple-500/10'
                : 'text-slate-400 hover:text-white hover:bg-white/5'
            }`}
          >
            <Activity className="w-4 h-4" />
            <span>التهديد الداخلي ({insiders.length})</span>
          </button>
        </div>

        {/* Tab Content */}
        {loading ? (
          <div className="h-[400px] flex items-center justify-center">
            <div className="flex items-center gap-3 text-slate-400 text-sm">
              <RefreshCw className="w-5 h-5 animate-spin text-primary" />
              <span>جاري تحميل بيانات الرسم البياني والترابط الجنائي...</span>
            </div>
          </div>
        ) : (
          <div>
            {activeTab === 'graph' && (
              <GraphCanvas
                nodes={graphData.nodes}
                edges={graphData.edges}
                selectedNodeId={selectedNode ? selectedNode.id : null}
                onSelectNode={(node) => setSelectedNode(node)}
              />
            )}

            {activeTab === 'chains' && (
              <AttackChainsList
                chains={chains}
                onPromote={(id) => handlePromote('attack_chain', id)}
                onViewInGraph={handleViewInGraph}
              />
            )}

            {activeTab === 'laterals' && (
              <LateralMovementsList
                movements={laterals}
                onPromote={(id) => handlePromote('lateral_movement', id)}
              />
            )}

            {activeTab === 'insiders' && (
              <InsiderThreatsList threats={insiders} />
            )}
          </div>
        )}

        {/* Node Details Slide-over Drawer */}
        <GraphEntityDrawer
          node={selectedNode}
          edges={graphData.edges}
          allNodes={graphData.nodes}
          onClose={() => setSelectedNode(null)}
          onSelectNode={(n) => setSelectedNode(n)}
        />
      </main>
    </div>
  );
}
