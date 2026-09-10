'use client';

import React, { useState } from 'react';
import { X, Server, Plus } from 'lucide-react';
import { createAsset } from '../../lib/api';
import { Asset, AssetType, AssetCriticality, AssetStatus } from '../../lib/types';

interface AddAssetModalProps {
  onClose: () => void;
  onSuccess: (asset: Asset) => void;
}

export function AddAssetModal({ onClose, onSuccess }: AddAssetModalProps) {
  const [hostname, setHostname] = useState('');
  const [primaryIp, setPrimaryIp] = useState('');
  const [macAddress, setMacAddress] = useState('');
  const [osName, setOsName] = useState('');
  const [assetType, setAssetType] = useState<AssetType>('server');
  const [criticality, setCriticality] = useState<AssetCriticality>('medium');
  const [status, setStatus] = useState<AssetStatus>('unknown');
  const [environment, setEnvironment] = useState('production');
  const [owner, setOwner] = useState('Unassigned');
  const [department, setDepartment] = useState('IT Operations');
  const [tags, setTags] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!hostname.trim() && !primaryIp.trim()) {
      setError('يرجى إدخال اسم المضيف أو عنوان الـ IP على الأقل.');
      return;
    }

    setLoading(true);
    setError(null);
    try {
      const tagList = tags.split(',').map(t => t.trim()).filter(Boolean);
      const res = await createAsset({
        hostname: hostname.trim() || primaryIp.trim(),
        primary_ip: primaryIp.trim() || '0.0.0.0',
        mac_address: macAddress.trim() || undefined,
        os: osName.trim() || 'Unknown',
        asset_type: assetType,
        criticality,
        status,
        environment,
        owner: owner.trim() || 'Unassigned',
        department: department.trim() || 'IT Operations',
        tags: tagList,
      });
      onSuccess(res);
      onClose();
    } catch (err: any) {
      setError(err.message || 'تعذر حفظ الأصل الأمني');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4 animate-fade-in">
      <div className="bg-dark-900 border border-white/10 rounded-2xl w-full max-w-xl shadow-2xl overflow-hidden animate-scale-up">
        <div className="p-5 border-b border-white/10 bg-dark-800/60 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-lg bg-primary/10 border border-primary/30 flex items-center justify-center text-primary">
              <Server className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-base font-bold text-white">إضافة أصل أمني جديد</h2>
              <p className="text-xs text-slate-400 mt-0.5">سجل الأصل في المخزون الموحد وتطبيق طبقة حل الهوية</p>
            </div>
          </div>
          <button onClick={onClose} className="p-1.5 rounded-lg hover:bg-white/10 text-slate-400 hover:text-white transition-colors">
            <X className="w-5 h-5" />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="p-5 space-y-4 text-xs">
          {error && (
            <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400">
              {error}
            </div>
          )}

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3.5">
            <div>
              <label className="block text-slate-400 mb-1 font-medium">اسم المضيف (Hostname) *</label>
              <input
                type="text"
                value={hostname}
                onChange={(e) => setHostname(e.target.value)}
                placeholder="e.g. DC-PRIMARY-01"
                className="w-full bg-dark-800 border border-white/10 rounded-lg p-2 text-white font-mono focus:border-primary outline-none"
              />
            </div>

            <div>
              <label className="block text-slate-400 mb-1 font-medium">عنوان الـ IP الرئيسي *</label>
              <input
                type="text"
                value={primaryIp}
                onChange={(e) => setPrimaryIp(e.target.value)}
                placeholder="e.g. 192.168.1.10"
                className="w-full bg-dark-800 border border-white/10 rounded-lg p-2 text-white font-mono focus:border-primary outline-none"
              />
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3.5">
            <div>
              <label className="block text-slate-400 mb-1 font-medium">عنوان MAC (اختياري)</label>
              <input
                type="text"
                value={macAddress}
                onChange={(e) => setMacAddress(e.target.value)}
                placeholder="e.g. 00:1A:2B:3C:4D:5E"
                className="w-full bg-dark-800 border border-white/10 rounded-lg p-2 text-white font-mono focus:border-primary outline-none"
              />
            </div>

            <div>
              <label className="block text-slate-400 mb-1 font-medium">نظام التشغيل</label>
              <input
                type="text"
                value={osName}
                onChange={(e) => setOsName(e.target.value)}
                placeholder="e.g. Windows Server 2022 / Ubuntu 22.04"
                className="w-full bg-dark-800 border border-white/10 rounded-lg p-2 text-white focus:border-primary outline-none"
              />
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3.5">
            <div>
              <label className="block text-slate-400 mb-1 font-medium">نوع الأصل</label>
              <select
                value={assetType}
                onChange={(e) => setAssetType(e.target.value as AssetType)}
                className="w-full bg-dark-800 border border-white/10 rounded-lg p-2 text-white focus:border-primary outline-none"
              >
                <option value="server">خادم (Server)</option>
                <option value="workstation">محطة عمل (Workstation)</option>
                <option value="domain_controller">متحكم نطاق (DC)</option>
                <option value="firewall">جدار حماية (Firewall)</option>
                <option value="database">قاعدة بيانات (Database)</option>
                <option value="cloud_instance">سحابة (Cloud Instance)</option>
                <option value="iot">جهاز IoT / شبكة</option>
              </select>
            </div>

            <div>
              <label className="block text-slate-400 mb-1 font-medium">مستوى الحرجية</label>
              <select
                value={criticality}
                onChange={(e) => setCriticality(e.target.value as AssetCriticality)}
                className="w-full bg-dark-800 border border-white/10 rounded-lg p-2 text-white focus:border-primary outline-none"
              >
                <option value="mission_critical">حرج للغاية (Mission Critical)</option>
                <option value="high">عالي (High)</option>
                <option value="medium">متوسط (Medium)</option>
                <option value="low">منخفض (Low)</option>
              </select>
            </div>

            <div>
              <label className="block text-slate-400 mb-1 font-medium">حالة الأصل</label>
              <select
                value={status}
                onChange={(e) => setStatus(e.target.value as AssetStatus)}
                className="w-full bg-dark-800 border border-white/10 rounded-lg p-2 text-white focus:border-primary outline-none"
              >
                <option value="unknown">غير مصنف (Unknown)</option>
                <option value="active">نشط (Active)</option>
                <option value="maintenance">صيانة (Maintenance)</option>
                <option value="isolated">معزول أمنياً (Isolated)</option>
              </select>
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3.5">
            <div>
              <label className="block text-slate-400 mb-1 font-medium">القسم التابع له</label>
              <input
                type="text"
                value={department}
                onChange={(e) => setDepartment(e.target.value)}
                placeholder="e.g. IT Operations, Finance, Security"
                className="w-full bg-dark-800 border border-white/10 rounded-lg p-2 text-white focus:border-primary outline-none"
              />
            </div>

            <div>
              <label className="block text-slate-400 mb-1 font-medium">المالك / المسؤول</label>
              <input
                type="text"
                value={owner}
                onChange={(e) => setOwner(e.target.value)}
                placeholder="e.g. John Doe / Security Team"
                className="w-full bg-dark-800 border border-white/10 rounded-lg p-2 text-white focus:border-primary outline-none"
              />
            </div>
          </div>

          <div>
            <label className="block text-slate-400 mb-1 font-medium">الوسوم (مفصولة بفاصلة)</label>
            <input
              type="text"
              value={tags}
              onChange={(e) => setTags(e.target.value)}
              placeholder="e.g. pci-dss, production, dmz, critical-infra"
              className="w-full bg-dark-800 border border-white/10 rounded-lg p-2 text-white focus:border-primary outline-none"
            />
          </div>

          <div className="pt-3 border-t border-white/10 flex items-center justify-end gap-2.5">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 rounded-lg bg-white/5 hover:bg-white/10 text-slate-300 transition-colors"
            >
              إلغاء
            </button>
            <button
              type="submit"
              disabled={loading}
              className="px-4 py-2 rounded-lg bg-primary hover:bg-primary/90 text-dark-950 font-bold transition-colors flex items-center gap-1.5"
            >
              <Plus className="w-4 h-4" />
              <span>حفظ الأصل</span>
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
