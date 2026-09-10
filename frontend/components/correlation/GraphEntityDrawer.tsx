'use client';

import React from 'react';
import { GraphNode, GraphEdge } from '../../lib/types';
import { X, User, Server, Cpu, FileText, Globe, ShieldAlert, Clock, ArrowRight, ArrowLeft, Copy } from 'lucide-react';

interface GraphEntityDrawerProps {
  node: GraphNode | null;
  edges: GraphEdge[];
  allNodes: GraphNode[];
  onClose: () => void;
  onSelectNode: (node: GraphNode) => void;
}

export function GraphEntityDrawer({ node, edges, allNodes, onClose, onSelectNode }: GraphEntityDrawerProps) {
  if (!node) return null;

  const nodeMap = new Map(allNodes.map((n) => [n.id, n]));
  const outgoing = edges.filter((e) => e.source_id === node.id);
  const incoming = edges.filter((e) => e.target_id === node.id);

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
  };

  return (
    <div className="fixed inset-y-0 left-0 w-full sm:w-96 bg-dark-900 border-r border-white/10 shadow-2xl z-50 flex flex-col backdrop-blur-xl animate-in slide-in-from-left duration-200">
      {/* Header */}
      <div className="p-4 border-b border-white/10 flex items-center justify-between bg-dark-950/60">
        <div className="flex items-center gap-2.5">
          <div className="p-2 rounded-lg bg-primary/10 border border-primary/30 text-primary">
            {node.node_type === 'user' && <User className="w-5 h-5 text-amber-400" />}
            {node.node_type === 'host' && <Server className="w-5 h-5 text-blue-400" />}
            {node.node_type === 'process' && <Cpu className="w-5 h-5 text-emerald-400" />}
            {node.node_type === 'file' && <FileText className="w-5 h-5 text-purple-400" />}
            {node.node_type === 'network' && <Globe className="w-5 h-5 text-red-400" />}
          </div>
          <div>
            <h3 className="text-sm font-bold text-white truncate max-w-[200px]" title={node.label}>
              {node.label}
            </h3>
            <span className="text-[11px] font-mono text-slate-400 uppercase">{node.node_type}</span>
          </div>
        </div>
        <button
          onClick={onClose}
          className="p-1.5 rounded-lg hover:bg-white/10 text-slate-400 hover:text-white transition-colors"
        >
          <X className="w-4 h-4" />
        </button>
      </div>

      {/* Body */}
      <div className="flex-1 overflow-y-auto p-4 space-y-5">
        {/* Risk & Criticality Banner */}
        <div className="grid grid-cols-2 gap-2">
          <div className="p-3 rounded-xl bg-white/5 border border-white/10">
            <span className="text-[11px] text-slate-400 block mb-1">مؤشر الخطورة (Risk)</span>
            <div className="flex items-center gap-2">
              <span className={`text-xl font-bold font-mono ${node.risk_score >= 75 ? 'text-red-400' : 'text-amber-400'}`}>
                {node.risk_score}
              </span>
              <span className="text-[10px] text-slate-500">/ 100</span>
            </div>
          </div>
          <div className="p-3 rounded-xl bg-white/5 border border-white/10">
            <span className="text-[11px] text-slate-400 block mb-1">الأهمية (Criticality)</span>
            <span className="text-sm font-bold text-slate-200 uppercase">{node.criticality}</span>
          </div>
        </div>

        {/* Node Properties */}
        <div>
          <h4 className="text-xs font-semibold text-slate-300 mb-2">الخصائص الفنية</h4>
          <div className="p-3 rounded-xl bg-dark-950 border border-white/10 space-y-2 text-xs">
            <div className="flex justify-between items-center py-1 border-b border-white/5">
              <span className="text-slate-400 font-mono text-[11px]">المعرف (ID):</span>
              <div className="flex items-center gap-1">
                <span className="text-slate-200 font-mono text-[11px] truncate max-w-[140px]">{node.id}</span>
                <button
                  onClick={() => copyToClipboard(node.id)}
                  className="text-slate-400 hover:text-primary transition-colors"
                  title="نسخ المعرف"
                >
                  <Copy className="w-3 h-3" />
                </button>
              </div>
            </div>
            {Object.entries(node.properties || {}).map(([key, val]) => (
              <div key={key} className="flex justify-between items-center py-1 border-b border-white/5">
                <span className="text-slate-400 font-mono text-[11px]">{key}:</span>
                <span className="text-slate-200 font-mono text-[11px] truncate max-w-[160px]">{String(val)}</span>
              </div>
            ))}
            <div className="flex justify-between items-center py-1">
              <span className="text-slate-400 text-[11px]">آخر ظهور:</span>
              <span className="text-slate-300 font-mono text-[10px]">
                {new Date(node.last_seen * 1000).toLocaleTimeString('ar-SA')}
              </span>
            </div>
          </div>
        </div>

        {/* Outgoing Relations */}
        <div>
          <h4 className="text-xs font-semibold text-slate-300 mb-2 flex items-center justify-between">
            <span className="flex items-center gap-1">
              <ArrowLeft className="w-3.5 h-3.5 text-primary" />
              <span>علاقات صادرة ({outgoing.length})</span>
            </span>
          </h4>
          {outgoing.length === 0 ? (
            <p className="text-xs text-slate-500 italic">لا توجد علاقات صادرة مسجلة.</p>
          ) : (
            <div className="space-y-1.5">
              {outgoing.map((e) => {
                const targetNode = nodeMap.get(e.target_id);
                return (
                  <div
                    key={e.id}
                    onClick={() => targetNode && onSelectNode(targetNode)}
                    className="p-2.5 rounded-lg bg-white/5 hover:bg-white/10 border border-white/5 cursor-pointer transition-colors flex items-center justify-between"
                  >
                    <div>
                      <span className="text-[10px] font-mono font-bold text-primary block">{e.relation_type}</span>
                      <span className="text-xs text-slate-200 font-medium">
                        {targetNode ? targetNode.label : e.target_id}
                      </span>
                    </div>
                    {e.weight >= 70 && (
                      <span className="px-1.5 py-0.5 rounded text-[9px] bg-red-500/20 text-red-400 font-bold font-mono">
                        {e.weight}
                      </span>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Incoming Relations */}
        <div>
          <h4 className="text-xs font-semibold text-slate-300 mb-2 flex items-center justify-between">
            <span className="flex items-center gap-1">
              <ArrowRight className="w-3.5 h-3.5 text-cyan-400" />
              <span>علاقات واردة ({incoming.length})</span>
            </span>
          </h4>
          {incoming.length === 0 ? (
            <p className="text-xs text-slate-500 italic">لا توجد علاقات واردة مسجلة.</p>
          ) : (
            <div className="space-y-1.5">
              {incoming.map((e) => {
                const srcNode = nodeMap.get(e.source_id);
                return (
                  <div
                    key={e.id}
                    onClick={() => srcNode && onSelectNode(srcNode)}
                    className="p-2.5 rounded-lg bg-white/5 hover:bg-white/10 border border-white/5 cursor-pointer transition-colors flex items-center justify-between"
                  >
                    <div>
                      <span className="text-[10px] font-mono font-bold text-cyan-400 block">{e.relation_type}</span>
                      <span className="text-xs text-slate-200 font-medium">
                        {srcNode ? srcNode.label : e.source_id}
                      </span>
                    </div>
                    {e.weight >= 70 && (
                      <span className="px-1.5 py-0.5 rounded text-[9px] bg-red-500/20 text-red-400 font-bold font-mono">
                        {e.weight}
                      </span>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
