'use client';

import React, { useState, useRef, useMemo } from 'react';
import { GraphNode, GraphEdge, GraphNodeType } from '../../lib/types';
import { User, Server, Cpu, FileText, Globe, ZoomIn, ZoomOut, RotateCcw, ShieldAlert, Layers } from 'lucide-react';

interface GraphCanvasProps {
  nodes: GraphNode[];
  edges: GraphEdge[];
  selectedNodeId: string | null;
  onSelectNode: (node: GraphNode) => void;
}

const TYPE_CONFIG: Record<GraphNodeType, { color: string; bg: string; border: string; label: string; icon: any }> = {
  user: { color: 'text-amber-400', bg: 'bg-amber-500/20', border: 'border-amber-500/50', label: 'مستخدم', icon: User },
  host: { color: 'text-blue-400', bg: 'bg-blue-500/20', border: 'border-blue-500/50', label: 'جهاز / أصل', icon: Server },
  process: { color: 'text-emerald-400', bg: 'bg-emerald-500/20', border: 'border-emerald-500/50', label: 'عملية', icon: Cpu },
  file: { color: 'text-purple-400', bg: 'bg-purple-500/20', border: 'border-purple-500/50', label: 'ملف / تجزئة', icon: FileText },
  network: { color: 'text-red-400', bg: 'bg-red-500/20', border: 'border-red-500/50', label: 'شبكة / C2', icon: Globe },
};

export function GraphCanvas({ nodes, edges, selectedNodeId, onSelectNode }: GraphCanvasProps) {
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [isDragging, setIsDragging] = useState(false);
  const [dragStart, setDragStart] = useState({ x: 0, y: 0 });
  const containerRef = useRef<HTMLDivElement>(null);

  // Compute Layout: Hierarchical columns from left to right (User -> Host -> Process -> File -> Network)
  const nodePositions = useMemo(() => {
    const positions: Record<string, { x: number; y: number }> = {};
    const grouped: Record<string, GraphNode[]> = {
      user: [],
      host: [],
      process: [],
      file: [],
      network: [],
    };

    nodes.forEach((n) => {
      const type = n.node_type in grouped ? n.node_type : 'host';
      grouped[type].push(n);
    });

    const colX: Record<string, number> = {
      user: 140,
      host: 420,
      process: 700,
      file: 980,
      network: 1260,
    };

    Object.entries(grouped).forEach(([type, groupNodes]) => {
      const x = colX[type] || 500;
      const total = groupNodes.length;
      const spacing = total > 8 ? 70 : 100;
      const startY = Math.max(80, 400 - (total * spacing) / 2);

      groupNodes.forEach((node, idx) => {
        positions[node.id] = {
          x,
          y: startY + idx * spacing,
        };
      });
    });

    return positions;
  }, [nodes]);

  const handleMouseDown = (e: React.MouseEvent) => {
    if (e.button === 0) {
      setIsDragging(true);
      setDragStart({ x: e.clientX - pan.x, y: e.clientY - pan.y });
    }
  };

  const handleMouseMove = (e: React.MouseEvent) => {
    if (isDragging) {
      setPan({
        x: e.clientX - dragStart.x,
        y: e.clientY - dragStart.y,
      });
    }
  };

  const handleMouseUp = () => setIsDragging(false);

  const resetView = () => {
    setZoom(1);
    setPan({ x: 0, y: 0 });
  };

  return (
    <div
      ref={containerRef}
      className="relative w-full h-[620px] bg-dark-950/90 rounded-2xl border border-white/10 overflow-hidden select-none cursor-grab active:cursor-grabbing shadow-inner"
      onMouseDown={handleMouseDown}
      onMouseMove={handleMouseMove}
      onMouseUp={handleMouseUp}
      onMouseLeave={handleMouseUp}
    >
      {/* Grid Pattern Background */}
      <div
        className="absolute inset-0 opacity-20 pointer-events-none"
        style={{
          backgroundImage: 'radial-gradient(#6366f1 1px, transparent 1px)',
          backgroundSize: '28px 28px',
          transform: `translate(${pan.x % 28}px, ${pan.y % 28}px)`,
        }}
      />

      {/* Floating Control Toolbar */}
      <div className="absolute top-4 left-4 z-20 flex items-center gap-1.5 p-1 rounded-xl bg-dark-900/90 border border-white/10 shadow-lg backdrop-blur-md">
        <button
          onClick={() => setZoom((z) => Math.min(2.5, z + 0.15))}
          className="p-2 rounded-lg hover:bg-white/10 text-slate-300 hover:text-white transition-colors"
          title="تكبير (Zoom In)"
        >
          <ZoomIn className="w-4 h-4" />
        </button>
        <button
          onClick={() => setZoom((z) => Math.max(0.4, z - 0.15))}
          className="p-2 rounded-lg hover:bg-white/10 text-slate-300 hover:text-white transition-colors"
          title="تصغير (Zoom Out)"
        >
          <ZoomOut className="w-4 h-4" />
        </button>
        <div className="w-px h-5 bg-white/10 mx-0.5" />
        <button
          onClick={resetView}
          className="p-2 rounded-lg hover:bg-white/10 text-slate-300 hover:text-white transition-colors"
          title="إعادة ضبط الرؤية"
        >
          <RotateCcw className="w-4 h-4" />
        </button>
        <span className="text-[11px] font-mono text-slate-400 px-2">
          {Math.round(zoom * 100)}%
        </span>
      </div>

      {/* Type Legend */}
      <div className="absolute top-4 right-4 z-20 flex items-center gap-2 p-2 rounded-xl bg-dark-900/90 border border-white/10 shadow-lg backdrop-blur-md text-xs">
        {Object.entries(TYPE_CONFIG).map(([type, cfg]) => {
          const Icon = cfg.icon;
          return (
            <div key={type} className="flex items-center gap-1.5 px-2 py-1 rounded-md bg-white/5 border border-white/5">
              <Icon className={`w-3.5 h-3.5 ${cfg.color}`} />
              <span className="text-slate-300 text-[11px]">{cfg.label}</span>
            </div>
          );
        })}
      </div>

      {/* Main SVG Graph Surface */}
      <svg
        className="w-full h-full"
        style={{
          transform: `translate(${pan.x}px, ${pan.y}px) scale(${zoom})`,
          transformOrigin: '0 0',
        }}
      >
        <defs>
          <marker
            id="arrowhead"
            markerWidth="10"
            markerHeight="7"
            refX="22"
            refY="3.5"
            orient="auto"
          >
            <polygon points="0 0, 10 3.5, 0 7" fill="#64748b" />
          </marker>
          <marker
            id="arrowhead-danger"
            markerWidth="10"
            markerHeight="7"
            refX="22"
            refY="3.5"
            orient="auto"
          >
            <polygon points="0 0, 10 3.5, 0 7" fill="#ef4444" />
          </marker>
        </defs>

        {/* Render Edges */}
        {edges.map((edge) => {
          const sPos = nodePositions[edge.source_id];
          const tPos = nodePositions[edge.target_id];
          if (!sPos || !tPos) return null;

          const isSelected = selectedNodeId && (edge.source_id === selectedNodeId || edge.target_id === selectedNodeId);
          const isHighWeight = edge.weight >= 70;
          const strokeColor = isSelected ? '#a855f7' : isHighWeight ? '#ef4444' : '#475569';
          const strokeWidth = isSelected ? 2.5 : isHighWeight ? 2 : 1.2;

          // Bezier curve
          const dx = tPos.x - sPos.x;
          const dy = tPos.y - sPos.y;
          const cx = sPos.x + dx / 2;
          const cy = sPos.y + dy / 2 - 20;

          return (
            <g key={edge.id} className="transition-opacity">
              <path
                d={`M ${sPos.x} ${sPos.y} Q ${cx} ${cy} ${tPos.x} ${tPos.y}`}
                fill="none"
                stroke={strokeColor}
                strokeWidth={strokeWidth}
                strokeDasharray={isHighWeight ? '4 2' : 'none'}
                markerEnd={isHighWeight ? 'url(#arrowhead-danger)' : 'url(#arrowhead)'}
                opacity={selectedNodeId ? (isSelected ? 1 : 0.25) : 0.75}
              />
              {/* Relation Label */}
              <text
                x={cx}
                y={cy - 4}
                fill={isSelected ? '#d8b4fe' : '#94a3b8'}
                fontSize="9"
                fontFamily="monospace"
                textAnchor="middle"
                className="pointer-events-none select-none"
                opacity={selectedNodeId ? (isSelected ? 1 : 0.2) : 0.8}
              >
                {edge.relation_type}
              </text>
            </g>
          );
        })}

        {/* Render Nodes */}
        {nodes.map((node) => {
          const pos = nodePositions[node.id];
          if (!pos) return null;

          const cfg = TYPE_CONFIG[node.node_type] || TYPE_CONFIG.host;
          const Icon = cfg.icon;
          const isSelected = selectedNodeId === node.id;
          const isHighRisk = node.risk_score >= 75;

          return (
            <g
              key={node.id}
              transform={`translate(${pos.x}, ${pos.y})`}
              onClick={(e) => {
                e.stopPropagation();
                onSelectNode(node);
              }}
              className="cursor-pointer group"
            >
              {/* Pulsing ring for high risk */}
              {isHighRisk && (
                <circle
                  r="24"
                  fill="none"
                  stroke="#ef4444"
                  strokeWidth="2"
                  className="animate-ping opacity-30"
                />
              )}

              {/* Node Outer Circle */}
              <circle
                r="18"
                fill="#0f172a"
                stroke={isSelected ? '#a855f7' : isHighRisk ? '#ef4444' : cfg.color.replace('text-', '')}
                strokeWidth={isSelected ? '3' : '2'}
                className="transition-all group-hover:scale-110 shadow-lg"
              />

              {/* Icon */}
              <foreignObject x="-10" y="-10" width="20" height="20" className="pointer-events-none">
                <div className="w-full h-full flex items-center justify-center">
                  <Icon className={`w-4 h-4 ${cfg.color}`} />
                </div>
              </foreignObject>

              {/* Risk Score Pill */}
              {node.risk_score > 0 && (
                <g transform="translate(12, -12)">
                  <circle r="8" fill={isHighRisk ? '#ef4444' : '#f59e0b'} />
                  <text
                    y="3"
                    fill="#ffffff"
                    fontSize="8"
                    fontWeight="bold"
                    textAnchor="middle"
                    className="select-none font-mono"
                  >
                    {node.risk_score}
                  </text>
                </g>
              )}

              {/* Node Label */}
              <text
                y="30"
                fill={isSelected ? '#ffffff' : '#cbd5e1'}
                fontSize="11"
                fontWeight={isSelected ? 'bold' : 'normal'}
                textAnchor="middle"
                className="select-none transition-colors group-hover:fill-white font-medium"
              >
                {node.label.length > 20 ? `${node.label.substring(0, 18)}...` : node.label}
              </text>
            </g>
          );
        })}
      </svg>
    </div>
  );
}
