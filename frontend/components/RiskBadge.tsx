import React from 'react';

export function RiskBadge({ score, level }: { score?: number; level?: string }) {
  const s = score ?? 0;
  let color = 'bg-blue-500/20 text-blue-400 border-blue-500/30';
  let label = level || 'منخفض';

  if (s >= 85 || level === 'حرج') {
    color = 'bg-rose-500/20 text-rose-400 border-rose-500/30 glow-rose';
    label = 'حرج';
  } else if (s >= 70 || level === 'مرتفع') {
    color = 'bg-orange-500/20 text-orange-400 border-orange-500/30';
    label = 'مرتفع';
  } else if (s >= 40 || level === 'متوسط') {
    color = 'bg-amber-500/20 text-amber-400 border-amber-500/30';
    label = 'متوسط';
  }

  return (
    <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-bold border ${color}`}>
      <span className="w-1.5 h-1.5 rounded-full bg-current"></span>
      <span>{label}</span>
      {score !== undefined && <span className="font-mono opacity-80 font-normal">({score})</span>}
    </span>
  );
}
