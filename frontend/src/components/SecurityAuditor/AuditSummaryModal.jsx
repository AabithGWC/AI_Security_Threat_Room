import React from 'react';
import { CheckCircle2, X, Zap } from 'lucide-react';

export default function AuditSummaryModal({
  isOpen,
  onClose,
  threats = [],
  readinessScore,
}) {
  if (!isOpen) return null;

  // Map threats to actual applied updates
  const dynamicUpdates = threats.map((t) => {
    const title = t.title?.toLowerCase() || '';
    if (title.includes('prompt injection')) {
      return 'Prompt injection protection updated';
    }
    if (title.includes('delete tool guard') || title.includes('admin')) {
      return 'Tool access guard enabled';
    }
    if (title.includes('endpoint authentication')) {
      return 'Endpoint authentication enforced';
    }
    if (title.includes('token') || title.includes('leakage')) {
      return 'Secret & token protection activated';
    }
    if (title.includes('rate limit')) {
      return 'Rate limiting enabled';
    }
    if (title.includes('.env') || title.includes('git')) {
      return 'Environment secret protection applied';
    }
    return `${t.title || 'Security vector'} protection updated`;
  });

  const defaultUpdates = [
    'Prompt injection protection updated',
    'Tool access guard enabled',
    'Endpoint authentication enforced',
    'Secret & token protection activated',
    'Rate limiting enabled',
    'Environment secret protection applied',
  ];

  const updatesList = dynamicUpdates.length > 0 ? dynamicUpdates : defaultUpdates;

  return (
    <div className="fixed inset-0 bg-[#1E1235]/60 backdrop-blur-sm z-50 flex items-center justify-center p-4 animate-fade-up">
      <div className="bg-white border border-[#462C7D]/20 rounded-3xl p-6 sm:p-7 max-w-md w-full shadow-[0_25px_70px_-15px_rgba(70,44,125,0.35)] relative overflow-visible h-auto max-h-none">
        {/* Close Button Top-Right */}
        <button
          onClick={onClose}
          className="absolute top-4 right-4 p-2 text-slate-400 hover:text-[#462C7D] rounded-full hover:bg-[#462C7D]/10 transition-colors cursor-pointer"
          title="Close Modal"
        >
          <X className="w-5 h-5" />
        </button>

        {/* Modal Header */}
        <div className="flex items-center justify-between gap-3 mb-3 pr-6">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-2xl bg-gradient-to-br from-[#462C7D] via-[#831C91] to-[#D552A3] text-white flex items-center justify-center shadow-md shadow-[#462C7D]/25 shrink-0">
              <CheckCircle2 className="w-6 h-6 stroke-[2.2]" />
            </div>
            <h3 className="font-display font-bold text-[#462C7D] text-lg sm:text-xl">
              Security Audit Completed <span className="text-emerald-600">✓</span>
            </h3>
          </div>
        </div>

        {/* Security Status Section (Without 100% percentage value) */}
        <div className="bg-[#FAF8FC] border border-[#462C7D]/12 p-3.5 px-4 rounded-2xl mb-4 text-xs font-mono">
          <div className="text-[10px] font-bold uppercase tracking-wider text-[#831C91] mb-1">
            Security Status
          </div>
          <p className="font-bold text-[#462C7D] text-[13px]">
            All security issues have been successfully resolved.
          </p>
          <p className="text-slate-500 text-[11px] mt-0.5">
            System security verified and protected.
          </p>
        </div>

        {/* Changes & Updates Applied Section */}
        <div className="mb-5">
          <div className="text-[10.5px] font-bold uppercase tracking-wider text-[#462C7D] font-mono mb-2 flex items-center gap-1.5">
            <Zap className="w-3.5 h-3.5 text-[#831C91]" />
            <span>Changes & Updates Applied</span>
          </div>

          <div className="space-y-1.5">
            {updatesList.map((updateText, idx) => (
              <div
                key={idx}
                className="flex items-center gap-2.5 p-2 px-3 rounded-lg bg-white border border-[#462C7D]/10 shadow-2xs text-xs text-[#1E1235]"
              >
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600 shrink-0" />
                <span className="font-sans text-slate-700 font-medium text-[11.5px]">{updateText}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Footer — Single Close Button */}
        <div className="pt-3 border-t border-[#462C7D]/10">
          <button
            onClick={onClose}
            className="w-full py-2.5 rounded-xl text-xs font-bold text-white bg-gradient-to-r from-[#462C7D] to-[#831C91] hover:brightness-110 shadow-md shadow-[#462C7D]/20 transition-all cursor-pointer"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
}
