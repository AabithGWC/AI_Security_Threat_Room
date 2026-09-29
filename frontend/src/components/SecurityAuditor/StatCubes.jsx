import React from 'react';
import { AlertTriangle, AlertCircle, ShieldAlert, CheckCircle2 } from 'lucide-react';

export default function StatCubes({ counts }) {
  const stats = [
    {
      key: 'critical',
      label: 'CRITICAL',
      count: counts.critical || 0,
      icon: AlertTriangle,
      bgGrad: 'bg-gradient-to-br from-white via-[#FAF7FD] to-[#F3EDFC]',
      badgeStyle: 'bg-rose-100/80 text-rose-800 border-rose-300',
    },
    {
      key: 'high',
      label: 'HIGH',
      count: counts.high || 0,
      icon: AlertCircle,
      bgGrad: 'bg-gradient-to-br from-white via-[#FCF6FB] to-[#FCECF6]',
      badgeStyle: 'bg-pink-100/80 text-pink-800 border-pink-300',
    },
    {
      key: 'medium',
      label: 'MEDIUM',
      count: counts.medium || 0,
      icon: ShieldAlert,
      bgGrad: 'bg-gradient-to-br from-white via-[#FAF6FE] to-[#F5EDFD]',
      badgeStyle: 'bg-purple-100/80 text-[#5B2896] border-purple-300',
    },
    {
      key: 'resolved',
      label: 'RESOLVED',
      count: counts.resolved || 0,
      icon: CheckCircle2,
      bgGrad: 'bg-gradient-to-br from-white via-[#FAFAFE] to-[#F0EFF8]',
      badgeStyle: 'bg-emerald-100/80 text-emerald-800 border-emerald-300',
    },
  ];

  return (
    <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 sm:gap-4 w-full">
      {stats.map((s) => {
        const Icon = s.icon;
        return (
          <div
            key={s.key}
            className={`${s.bgGrad} border border-[#462C7D]/20 rounded-2xl min-h-[115px] sm:min-h-[125px] p-4.5 sm:p-5 px-5 flex flex-col justify-between transition-all duration-200 ease-out hover:-translate-y-0.5 hover:shadow-md hover:border-[#8E1E9E]/40 shadow-xs cursor-default`}
          >
            {/* Top Row: Count (Left) + Refined Icon Badge (Right) */}
            <div className="flex items-center justify-between">
              <span className="font-display text-2xl sm:text-3xl font-extrabold text-[#3C1F73] leading-none tracking-tight">
                {s.count}
              </span>
              <div className={`w-8 h-8 rounded-xl flex items-center justify-center border shadow-2xs font-bold shrink-0 ${s.badgeStyle}`}>
                <Icon className="w-4 h-4 stroke-[2.2]" />
              </div>
            </div>

            {/* Bottom Row: Label */}
            <div className="text-[11px] sm:text-xs font-bold uppercase tracking-wider text-[#4C2882] font-display mt-2">
              {s.label}
            </div>
          </div>
        );
      })}
    </div>
  );
}
