import React, { useState } from 'react';
import { ChevronDown, ChevronUp, Check, RefreshCw, Code, Tag, ExternalLink } from 'lucide-react';

export default function ThreatCard({
  threat,
  onFix,
  onRevoke,
  isProcessing,
  auditCompleted,
  onSelectThreat,
}) {
  const [expanded, setExpanded] = useState(false);

  const severityStyles = {
    critical: {
      badge: 'bg-rose-100/90 text-rose-800 border-rose-300 font-extrabold shadow-2xs',
    },
    high: {
      badge: 'bg-pink-100/90 text-pink-800 border-pink-300 font-extrabold shadow-2xs',
    },
    medium: {
      badge: 'bg-purple-100/90 text-[#5B2896] border-purple-300 font-extrabold',
    },
    resolved: {
      badge: 'bg-emerald-100/90 text-emerald-800 border-emerald-300 font-extrabold',
    },
  };

  const isResolved = threat.status === 'resolved';
  const style = severityStyles[isResolved ? 'resolved' : threat.severity?.toLowerCase()] || severityStyles.medium;

  const handleCardClick = () => {
    if (auditCompleted && onSelectThreat) {
      onSelectThreat(threat);
    }
  };

  return (
    <div
      onClick={handleCardClick}
      className={`bg-gradient-to-r from-white via-white to-[#FAF8FD] border border-[#462C7D]/22 rounded-xl overflow-hidden shadow-xs transition-all duration-200 ease-out mb-2.5 animate-fade-up ${
        auditCompleted
          ? 'cursor-pointer hover:-translate-y-0.5 hover:shadow-md hover:border-[#8E1E9E]/50 group'
          : 'cursor-default opacity-90'
      }`}
    >
      {/* Card Header */}
      <div className="p-3 px-4 flex items-center gap-3 select-none hover:bg-[#FAF8FC] transition-colors">
        {/* Threat Title */}
        <div className="flex-1 font-display font-extrabold text-[#1E1235] text-[13.5px] truncate flex items-center gap-2">
          <span>{threat.title || threat.summary || threat.id}</span>
          {auditCompleted && (
            <ExternalLink className="w-3 h-3 text-[#8E1E9E] opacity-0 group-hover:opacity-100 transition-opacity shrink-0" />
          )}
        </div>

        {/* Domain / Category Tag */}
        {(threat.domain || threat.category) && (
          <span className="hidden sm:inline-block font-mono text-[10px] text-[#3C1F73] bg-[#4C2882]/12 border border-[#4C2882]/25 px-2 py-0.5 rounded-md font-bold shrink-0">
            {threat.domain || threat.category}
          </span>
        )}

        {/* CVSS Score Tag */}
        {threat.cvss && (
          <span className="font-mono text-[10px] text-slate-700 bg-[#FAF8FC] border border-[#4C2882]/25 px-2 py-0.5 rounded-md shrink-0 font-bold shadow-2xs">
            CVSS {threat.cvss}
          </span>
        )}

        {/* Severity / Status Badge */}
        <span
          className={`text-[10px] uppercase tracking-wider px-2.5 py-0.5 rounded-md border shrink-0 font-mono ${style.badge}`}
        >
          {isResolved ? 'Resolved' : threat.severity}
        </span>

        {/* Expand / Collapse Chevron Icon */}
        <button
          onClick={(e) => {
            e.stopPropagation();
            setExpanded(!expanded);
          }}
          className="p-1 text-slate-400 hover:text-[#831C91] rounded-lg transition-colors cursor-pointer"
          title={expanded ? 'Collapse preview' : 'Expand preview'}
        >
          {expanded ? (
            <ChevronUp className="w-4 h-4 text-[#831C91] shrink-0" />
          ) : (
            <ChevronDown className="w-4 h-4 text-slate-400 shrink-0" />
          )}
        </button>
      </div>

      {/* Expanded Content Body */}
      {expanded && (
        <div className="p-3.5 sm:p-5 pt-1 border-t border-[#462C7D]/10 bg-[#FAF8FC]/60 text-xs space-y-3.5 sm:space-y-4">
          {/* Summary / Impact */}
          {threat.description && (
            <div className="mt-3">
              <span className="font-bold text-[#462C7D] block mb-1">Description & Impact</span>
              <p className="text-[#5A4D73] leading-relaxed font-sans">{threat.description}</p>
            </div>
          )}

          {/* CVE tags */}
          {threat.cve && (
            <div className="flex items-center gap-1.5 flex-wrap">
              <Tag className="w-3.5 h-3.5 text-[#831C91]" />
              <span className="font-mono text-slate-600 font-semibold">{threat.cve}</span>
            </div>
          )}

          {/* Code diff / Remediation preview */}
          {(threat.remediation || threat.originalCode) && (
            <div className="max-w-full">
              <div className="flex items-center gap-1.5 mb-2 font-bold text-[#462C7D]">
                <Code className="w-3.5 h-3.5 text-[#831C91]" />
                <span>Suggested Remediation</span>
              </div>
              <pre className="bg-[#1E1235] text-slate-100 p-3 sm:p-4 rounded-xl font-mono text-[11px] sm:text-[11.5px] overflow-x-auto leading-relaxed border border-[#462C7D]/30 shadow-inner whitespace-pre-wrap break-words max-w-full">
                {threat.remediation || threat.patchedCode}
              </pre>
            </div>
          )}

          {/* Actions */}
          <div className="flex flex-col xs:flex-row items-stretch xs:items-center justify-between gap-2.5 pt-3 border-t border-[#462C7D]/10">
            <div className="flex items-center gap-2">
              {isResolved ? (
                <button
                  onClick={(e) => {
                    e.stopPropagation();
                    onRevoke && onRevoke(threat.id);
                  }}
                  disabled={isProcessing}
                  className="flex items-center justify-center gap-1.5 px-4 py-2 rounded-xl text-xs font-extrabold text-[#9C2652] bg-white hover:bg-rose-50 border border-[#9C2652]/35 transition-all disabled:opacity-50 cursor-pointer shadow-2xs"
                >
                  <RefreshCw className={`w-3.5 h-3.5 ${isProcessing ? 'animate-spin' : ''}`} />
                  <span>{isProcessing ? 'Revoking...' : 'Revoke Fix'}</span>
                </button>
              ) : (
                <button
                  onClick={(e) => {
                    e.stopPropagation();
                    onFix && onFix(threat.id);
                  }}
                  disabled={isProcessing}
                  className="flex items-center justify-center gap-1.5 px-4 py-2 rounded-xl text-xs font-extrabold text-white bg-gradient-to-r from-[#4C2882] via-[#8E1E9E] to-[#D84BA1] hover:brightness-110 shadow-md shadow-[#4C2882]/20 transition-all disabled:opacity-50 cursor-pointer"
                >
                  <Check className={`w-3.5 h-3.5 ${isProcessing ? 'animate-spin' : ''}`} />
                  <span>{isProcessing ? 'Resolving...' : 'Fix Threat'}</span>
                </button>
              )}
            </div>

            {auditCompleted && (
              <span className="text-[10.5px] sm:text-[11px] font-mono text-[#8E1E9E] font-bold flex items-center gap-1">
                Click card for full threat details →
              </span>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
