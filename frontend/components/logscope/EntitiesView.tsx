'use client';

import React, { useState } from 'react';
import { User, Target, Laptop, Search, ExternalLink, ShieldAlert, ListFilter } from 'lucide-react';

interface EntitiesViewProps {
  entitiesSummary?: {
    top_users?: Array<{ username: string; count: number; critical: number; high: number; last_seen?: string }>;
    top_ips?: Array<{ ip: string; count: number; critical: number; high: number; destinations?: string[]; ports?: string[] }>;
    top_devices?: Array<{ device: string; count: number }>;
  };
  onSelectEntity: (type: 'user' | 'ip' | 'device', value: string) => void;
  onFilterEntity: (type: 'user' | 'ip' | 'device', value: string) => void;
}

export function EntitiesView({
  entitiesSummary,
  onSelectEntity,
  onFilterEntity,
}: EntitiesViewProps) {
  const [subTab, setSubTab] = useState<'users' | 'ips' | 'devices'>('users');
  const [search, setSearch] = useState('');

  const users = entitiesSummary?.top_users || [];
  const ips = entitiesSummary?.top_ips || [];
  const devices = entitiesSummary?.top_devices || [];

  const filteredUsers = users.filter((u) => u.username.toLowerCase().includes(search.toLowerCase()));
  const filteredIps = ips.filter((ip) => ip.ip.includes(search));
  const filteredDevices = devices.filter((d) => d.device.toLowerCase().includes(search.toLowerCase()));

  return (
    <div className="space-y-6">
      {/* Top Bar with Sub Tabs */}
      <div className="flex flex-wrap items-center justify-between gap-4 bg-dark-900/50 p-4 rounded-2xl border border-white/10">
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => setSubTab('users')}
            className={`flex items-center gap-1.5 px-4 py-2 rounded-xl text-xs font-bold transition-all ${
              subTab === 'users'
                ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                : 'text-slate-400 hover:text-white hover:bg-white/5 border border-transparent'
            }`}
          >
            <User className="w-3.5 h-3.5" />
            <span>الحسابات ({users.length})</span>
          </button>

          <button
            type="button"
            onClick={() => setSubTab('ips')}
            className={`flex items-center gap-1.5 px-4 py-2 rounded-xl text-xs font-bold transition-all ${
              subTab === 'ips'
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30'
                : 'text-slate-400 hover:text-white hover:bg-white/5 border border-transparent'
            }`}
          >
            <Target className="w-3.5 h-3.5" />
            <span>عناوين IP ({ips.length})</span>
          </button>

          <button
            type="button"
            onClick={() => setSubTab('devices')}
            className={`flex items-center gap-1.5 px-4 py-2 rounded-xl text-xs font-bold transition-all ${
              subTab === 'devices'
                ? 'bg-purple-500/20 text-purple-300 border border-purple-500/30'
                : 'text-slate-400 hover:text-white hover:bg-white/5 border border-transparent'
            }`}
          >
            <Laptop className="w-3.5 h-3.5" />
            <span>الأجهزة ({devices.length})</span>
          </button>
        </div>

        <div className="relative">
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="بحث في الكيانات..."
            className="bg-black/30 border border-white/10 rounded-xl px-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:border-emerald-500 focus:outline-none w-60 pr-8"
          />
          <Search className="w-3.5 h-3.5 text-slate-400 absolute right-2.5 top-2.5" />
        </div>
      </div>

      {/* Grid of User Accounts */}
      {subTab === 'users' && (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {filteredUsers.map((u) => (
            <div
              key={u.username}
              className="p-4 rounded-2xl border border-white/10 bg-dark-900/60 hover:border-emerald-500/30 transition-all space-y-3 flex flex-col justify-between"
            >
              <div>
                <div className="flex items-start justify-between gap-2">
                  <div className="flex items-center gap-2 min-w-0">
                    <div className="p-2 rounded-xl bg-emerald-500/10 text-emerald-400">
                      <User className="w-4 h-4" />
                    </div>
                    <span className="font-extrabold text-white text-sm truncate" dir="auto">
                      {u.username}
                    </span>
                  </div>
                  <span className="px-2 py-0.5 rounded font-mono text-xs font-bold bg-white/5 text-slate-300">
                    {u.count.toLocaleString('en-US')} حدث
                  </span>
                </div>

                <div className="flex items-center gap-3 mt-3 text-xs">
                  {u.critical > 0 && <span className="text-rose-400 font-bold">{u.critical} حرج</span>}
                  {u.high > 0 && <span className="text-amber-400 font-bold">{u.high} مرتفع</span>}
                  {u.last_seen && <span className="text-slate-500 font-mono text-[10px] mr-auto">{u.last_seen}</span>}
                </div>
              </div>

              <div className="pt-3 border-t border-white/5 flex items-center justify-between">
                <button
                  type="button"
                  onClick={() => onSelectEntity('user', u.username)}
                  className="text-xs font-bold text-emerald-400 hover:text-emerald-300 inline-flex items-center gap-1"
                >
                  <span>فحص السجل الجنائي</span>
                  <ExternalLink className="w-3 h-3" />
                </button>
                <button
                  type="button"
                  onClick={() => onFilterEntity('user', u.username)}
                  className="px-2.5 py-1 rounded-lg bg-white/5 hover:bg-white/10 border border-white/10 text-slate-300 text-[11px] font-bold"
                >
                  تصفية
                </button>
              </div>
            </div>
          ))}

          {filteredUsers.length === 0 && (
            <div className="col-span-full p-8 text-center text-slate-400 text-xs bg-dark-900/40 rounded-xl border border-white/5">
              لا توجد حسابات مسجلة أو مطابقة للبحث.
            </div>
          )}
        </div>
      )}

      {/* Grid of IP Addresses */}
      {subTab === 'ips' && (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {filteredIps.map((ip) => (
            <div
              key={ip.ip}
              className="p-4 rounded-2xl border border-white/10 bg-dark-900/60 hover:border-cyan-500/30 transition-all space-y-3 flex flex-col justify-between"
            >
              <div>
                <div className="flex items-start justify-between gap-2">
                  <div className="flex items-center gap-2 min-w-0">
                    <div className="p-2 rounded-xl bg-cyan-500/10 text-cyan-400">
                      <Target className="w-4 h-4" />
                    </div>
                    <span className="font-extrabold text-white text-sm font-mono truncate" dir="ltr">
                      {ip.ip}
                    </span>
                  </div>
                  <span className="px-2 py-0.5 rounded font-mono text-xs font-bold bg-white/5 text-slate-300">
                    {ip.count.toLocaleString('en-US')} حدث
                  </span>
                </div>

                <div className="flex items-center gap-3 mt-3 text-xs">
                  {ip.critical > 0 && <span className="text-rose-400 font-bold">{ip.critical} حرج</span>}
                  {ip.high > 0 && <span className="text-amber-400 font-bold">{ip.high} مرتفع</span>}
                  {ip.ports && ip.ports.length > 0 && (
                    <span className="text-slate-500 font-mono text-[10px] mr-auto">
                      المنافذ: {ip.ports.slice(0, 3).join(', ')}
                    </span>
                  )}
                </div>
              </div>

              <div className="pt-3 border-t border-white/5 flex items-center justify-between">
                <button
                  type="button"
                  onClick={() => onSelectEntity('ip', ip.ip)}
                  className="text-xs font-bold text-cyan-400 hover:text-cyan-300 inline-flex items-center gap-1"
                >
                  <span>فحص السجل الجنائي</span>
                  <ExternalLink className="w-3 h-3" />
                </button>
                <button
                  type="button"
                  onClick={() => onFilterEntity('ip', ip.ip)}
                  className="px-2.5 py-1 rounded-lg bg-white/5 hover:bg-white/10 border border-white/10 text-slate-300 text-[11px] font-bold"
                >
                  تصفية
                </button>
              </div>
            </div>
          ))}

          {filteredIps.length === 0 && (
            <div className="col-span-full p-8 text-center text-slate-400 text-xs bg-dark-900/40 rounded-xl border border-white/5">
              لا توجد عناوين IP مطابقة للبحث.
            </div>
          )}
        </div>
      )}

      {/* Grid of Devices */}
      {subTab === 'devices' && (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {filteredDevices.map((dev) => (
            <div
              key={dev.device}
              className="p-4 rounded-2xl border border-white/10 bg-dark-900/60 hover:border-purple-500/30 transition-all space-y-3 flex flex-col justify-between"
            >
              <div>
                <div className="flex items-start justify-between gap-2">
                  <div className="flex items-center gap-2 min-w-0">
                    <div className="p-2 rounded-xl bg-purple-500/10 text-purple-400">
                      <Laptop className="w-4 h-4" />
                    </div>
                    <span className="font-extrabold text-white text-sm font-mono truncate">
                      {dev.device}
                    </span>
                  </div>
                  <span className="px-2 py-0.5 rounded font-mono text-xs font-bold bg-white/5 text-slate-300">
                    {dev.count.toLocaleString('en-US')} حدث
                  </span>
                </div>
              </div>

              <div className="pt-3 border-t border-white/5 flex items-center justify-between">
                <button
                  type="button"
                  onClick={() => onSelectEntity('device', dev.device)}
                  className="text-xs font-bold text-purple-400 hover:text-purple-300 inline-flex items-center gap-1"
                >
                  <span>فحص السجل</span>
                  <ExternalLink className="w-3 h-3" />
                </button>
                <button
                  type="button"
                  onClick={() => onFilterEntity('device', dev.device)}
                  className="px-2.5 py-1 rounded-lg bg-white/5 hover:bg-white/10 border border-white/10 text-slate-300 text-[11px] font-bold"
                >
                  تصفية
                </button>
              </div>
            </div>
          ))}

          {filteredDevices.length === 0 && (
            <div className="col-span-full p-8 text-center text-slate-400 text-xs bg-dark-900/40 rounded-xl border border-white/5">
              لا توجد أجهزة مطابقة للبحث.
            </div>
          )}
        </div>
      )}
    </div>
  );
}
