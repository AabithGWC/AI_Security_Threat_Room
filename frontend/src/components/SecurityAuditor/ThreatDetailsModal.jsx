import React, { useState, useEffect } from 'react';
import { X, ShieldAlert, CheckCircle2 } from 'lucide-react';

export default function ThreatDetailsModal({
  threat,
  isOpen,
  onClose,
  onResolve,
  isWorking = false,
}) {
  const [renderModal, setRenderModal] = useState(false);
  const [isClosing, setIsClosing] = useState(false);
  const [isActive, setIsActive] = useState(false);

  // Sync mount and unmount animation state
  useEffect(() => {
    if (isOpen) {
      setRenderModal(true);
      setIsClosing(false);
      const rAF = requestAnimationFrame(() => {
        requestAnimationFrame(() => {
          setIsActive(true);
        });
      });
      return () => cancelAnimationFrame(rAF);
    } else if (renderModal && !isClosing) {
      setIsActive(false);
      setIsClosing(true);
      const timer = setTimeout(() => {
        setRenderModal(false);
        setIsClosing(false);
      }, 420);
      return () => clearTimeout(timer);
    }
  }, [isOpen, renderModal, isClosing]);

  // Smooth close handler with animation delay (cubic-bezier easing, ~420ms)
  const handleSmoothClose = () => {
    if (isClosing) return;
    setIsActive(false);
    setIsClosing(true);
    setTimeout(() => {
      onClose();
      setRenderModal(false);
      setIsClosing(false);
    }, 420);
  };

  // Resolve click handler: executes resolve then plays smooth closing animation
  const handleResolveClick = (e) => {
    e.stopPropagation();
    if (isWorking || isClosing) return;
    if (onResolve && threat?.id) {
      onResolve(threat.id);
    }
    handleSmoothClose();
  };

  // ESC KEY HANDLER & SCROLL LOCK
  useEffect(() => {
    if (!renderModal) return;

    const handleKeyDown = (e) => {
      if (e.key === 'Escape') {
        handleSmoothClose();
      }
    };

    const originalOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';

    window.addEventListener('keydown', handleKeyDown);

    return () => {
      document.body.style.overflow = originalOverflow;
      window.removeEventListener('keydown', handleKeyDown);
    };
  }, [renderModal, isClosing]);

  if (!renderModal || !threat) return null;

  const isResolved = threat.status === 'resolved';
  const severityUpper = (threat.severity || 'HIGH').toUpperCase();
  const isHighOrCritical = severityUpper === 'CRITICAL' || severityUpper === 'HIGH';

  // Severity Badge Styling
  const getSeverityBadgeStyle = () => {
    if (isResolved) {
      return 'bg-emerald-100/90 text-emerald-800 border-emerald-300 font-extrabold';
    }
    if (isHighOrCritical) {
      return 'bg-rose-100/90 text-rose-800 border-rose-300 font-extrabold shadow-2xs';
    }
    return 'bg-amber-100/90 text-amber-800 border-amber-300 font-extrabold';
  };

  // Helper to ensure code panels display only the actual source code
  const cleanCodeSnippet = (code) => {
    if (!code) return '// Code snapshot not available';
    const lines = code.split('\n');
    let startIndex = 0;
    while (startIndex < lines.length) {
      const trimmed = lines[startIndex].trim();
      // Match non-code leading header lines / comment labels
      const isHeaderComment =
        (trimmed.startsWith('#') && (
          trimmed.includes('.py') ||
          trimmed.includes('.js') ||
          trimmed.includes('.gitignore') ||
          trimmed.includes('—') ||
          trimmed.includes('--') ||
          trimmed.includes('raw user') ||
          trimmed.includes('sanitized') ||
          trimmed.includes('endpoint') ||
          trimmed.includes('unauthenticated') ||
          trimmed.includes('authenticated') ||
          trimmed.includes('unmasked') ||
          trimmed.includes('unlimited') ||
          trimmed.includes('execute_tool') ||
          trimmed.includes('no exclusion') ||
          trimmed.includes('secrets properly') ||
          trimmed.includes('without .env')
        )) ||
        (trimmed.startsWith('//') && (
          trimmed.toLowerCase().includes('before') ||
          trimmed.toLowerCase().includes('after') ||
          trimmed.toLowerCase().includes('secured') ||
          trimmed.toLowerCase().includes('implementation') ||
          trimmed.toLowerCase().includes('mitigation')
        ));

      if (isHeaderComment || trimmed === '') {
        startIndex++;
      } else {
        break;
      }
    }
    const result = lines.slice(startIndex).join('\n');
    return result.trim() ? result : code;
  };

  // Field values with fallbacks
  const titleText = threat.title || 'Security Threat Details';
  const categoryText = threat.category || threat.domain || 'Security Analysis';
  const cvssText = threat.cvss ? String(threat.cvss) : null;
  const descriptionText = threat.description || 'Details not available for this finding.';
  const attackScenarioText = threat.attackScenario || 'Details not available for this finding.';
  const businessImpactText = threat.businessImpact || 'Details not available for this finding.';
  const originalCodeText = cleanCodeSnippet(threat.originalCode || threat.diff_before || '// Code snapshot not available');
  const patchedCodeText = cleanCodeSnippet(threat.patchedCode || threat.diff_after || '// Security patch snapshot not available');
  const expectedChangesText = threat.expectedChanges || 'Details not available for this finding.';
  const whyThisMattersText = threat.whyThisMatters || 'Details not available for this finding.';

  const remediationSteps =
    Array.isArray(threat.remediationSteps) && threat.remediationSteps.length > 0
      ? threat.remediationSteps
      : ['Details not available for this finding.'];

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="threat-modal-title"
      onClick={handleSmoothClose}
      className={`fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-6 transition-all duration-[420ms] ease-[cubic-bezier(0.4,0,0.2,1)] ${
        isActive && !isClosing
          ? 'bg-[#362352]/35 backdrop-blur-[5px] opacity-100 pointer-events-auto'
          : 'bg-[#362352]/0 backdrop-blur-none opacity-0 pointer-events-none'
      }`}
    >
      {/* Custom inline style for hidden scrollbar */}
      <style>{`
        .modal-no-scrollbar::-webkit-scrollbar {
          display: none !important;
          width: 0 !important;
          height: 0 !important;
        }
        .modal-no-scrollbar {
          -ms-overflow-style: none !important;
          scrollbar-width: none !important;
        }
      `}</style>

      {/* Light Mode Professional Modal Card */}
      <div
        onClick={(e) => e.stopPropagation()}
        className={`bg-white text-slate-800 border border-[#462C7D]/25 rounded-[20px] sm:rounded-[24px] p-4 sm:p-7 shadow-[0_25px_75px_-12px_rgba(70,44,125,0.3)] relative flex flex-col w-[calc(100vw-20px)] md:w-[min(1150px,calc(100vw-48px))] max-h-[85vh] sm:max-h-[88vh] overflow-hidden transition-all duration-[420ms] ${
          isActive && !isClosing
            ? 'opacity-100 scale-100 translate-y-0 ease-[cubic-bezier(0.16,1,0.3,1)]'
            : 'opacity-0 scale-[0.96] translate-y-2.5 ease-[cubic-bezier(0.4,0,0.2,1)]'
        }`}
      >
        {/* Header */}
        <div className="flex items-start justify-between gap-3 pb-3 sm:pb-4 mb-3 sm:mb-4 border-b border-[#462C7D]/20 shrink-0 pr-8">
          <div className="flex flex-col gap-2">
            {/* Title */}
            <h2
              id="threat-modal-title"
              className="font-display font-bold text-[#3B1F73] text-base sm:text-xl leading-snug"
            >
              {titleText}
            </h2>

            {/* Badges Row */}
            <div className="flex items-center gap-2 flex-wrap font-mono text-[10px] sm:text-[11px]">
              {categoryText && (
                <span className="px-2.5 py-0.5 rounded-md bg-[#462C7D]/12 text-[#462C7D] border border-[#462C7D]/25 font-bold">
                  {categoryText}
                </span>
              )}

              {cvssText && (
                <span className="px-2.5 py-0.5 rounded-md bg-[#FAF8FC] text-slate-700 border border-[#462C7D]/25 font-bold shadow-2xs">
                  CVSS {cvssText}
                </span>
              )}

              <span
                className={`px-2.5 py-0.5 rounded-md border font-bold uppercase ${getSeverityBadgeStyle()}`}
              >
                {isResolved ? 'RESOLVED' : severityUpper}
              </span>
            </div>
          </div>

          {/* Close Button */}
          <button
            onClick={handleSmoothClose}
            aria-label="Close modal"
            className="absolute top-4 right-4 p-1.5 text-slate-400 hover:text-[#462C7D] hover:bg-[#462C7D]/10 rounded-lg transition-colors cursor-pointer"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Scrollable Body — Hidden Scrollbar */}
        <div className="flex-1 overflow-y-auto space-y-4 pr-1 text-[13px] sm:text-[13.5px] leading-relaxed text-slate-800 modal-no-scrollbar">
          {/* 1. THREAT DESCRIPTION */}
          <section>
            <span className="font-mono text-[10.5px] sm:text-[11px] font-extrabold uppercase tracking-wider text-[#462C7D] mb-1.5 block">
              THREAT DESCRIPTION
            </span>
            <p className="text-slate-800 font-medium leading-relaxed font-sans">{descriptionText}</p>
          </section>

          {/* 2. ATTACK SCENARIO + BUSINESS IMPACT */}
          <section className="grid grid-cols-1 md:grid-cols-2 gap-3.5">
            {/* Attack Scenario Box */}
            <div className="bg-[#FAF8FD] border border-[#462C7D]/20 rounded-xl p-3.5 sm:p-4 shadow-2xs hover:border-[#831C91]/35 transition-colors">
              <span className="font-mono text-[10.5px] sm:text-[11px] font-extrabold uppercase tracking-wider text-[#462C7D] mb-1.5 block">
                ATTACK SCENARIO
              </span>
              <p className="text-slate-800 font-medium leading-relaxed font-sans">{attackScenarioText}</p>
            </div>

            {/* Business Impact Box */}
            <div className="bg-[#FAF8FD] border border-[#462C7D]/20 rounded-xl p-3.5 sm:p-4 shadow-2xs hover:border-[#831C91]/35 transition-colors">
              <span className="font-mono text-[10.5px] sm:text-[11px] font-extrabold uppercase tracking-wider text-[#462C7D] mb-1.5 block">
                BUSINESS IMPACT
              </span>
              <p className="text-slate-800 font-medium leading-relaxed font-sans">{businessImpactText}</p>
            </div>
          </section>

          {/* 3. ORIGINAL CODE — BEFORE + PATCHED CODE — AFTER */}
          <section className="grid grid-cols-1 md:grid-cols-2 gap-3.5">
            {/* Before Box */}
            <div className="bg-rose-50/90 border border-rose-200/90 rounded-xl p-3.5 sm:p-4 flex flex-col max-w-full shadow-2xs">
              <span className="font-mono text-[10.5px] sm:text-[11px] font-extrabold uppercase tracking-wider text-rose-800 mb-2 block flex items-center gap-1.5">
                <ShieldAlert className="w-3.5 h-3.5 text-rose-600 stroke-[2.5]" />
                <span>ORIGINAL CODE — BEFORE</span>
              </span>
              <pre className="font-mono text-[11px] sm:text-[12px] text-slate-900 bg-white p-3 sm:p-3.5 rounded-lg border border-rose-200 leading-relaxed whitespace-pre-wrap break-words max-w-full overflow-x-auto flex-1 shadow-inner">
                {originalCodeText}
              </pre>
            </div>

            {/* After Box */}
            <div className="bg-emerald-50/90 border border-emerald-200/90 rounded-xl p-3.5 sm:p-4 flex flex-col max-w-full shadow-2xs">
              <span className="font-mono text-[10.5px] sm:text-[11px] font-extrabold uppercase tracking-wider text-emerald-800 mb-2 block flex items-center gap-1.5">
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600 stroke-[2.5]" />
                <span>PATCHED CODE — AFTER</span>
              </span>
              <pre className="font-mono text-[11px] sm:text-[12px] text-slate-900 bg-white p-3 sm:p-3.5 rounded-lg border border-emerald-200 leading-relaxed whitespace-pre-wrap break-words max-w-full overflow-x-auto flex-1 shadow-inner">
                {patchedCodeText}
              </pre>
            </div>
          </section>

          {/* 4. EXPECTED CHANGES */}
          <section className="bg-[#FAF8FD] border border-[#462C7D]/20 rounded-xl p-3.5 sm:p-4 shadow-2xs hover:border-[#831C91]/35 transition-colors">
            <span className="font-mono text-[10.5px] sm:text-[11px] font-extrabold uppercase tracking-wider text-[#462C7D] mb-1.5 block">
              EXPECTED CHANGES
            </span>
            <p className="text-slate-800 font-medium leading-relaxed font-sans">{expectedChangesText}</p>
          </section>

          {/* 5. WHY THIS MATTERS */}
          <section className="bg-gradient-to-r from-[#FAF6FE] via-[#F6EDFC] to-[#F0E4FA] border border-[#831C91]/35 rounded-xl p-3.5 sm:p-4 shadow-xs">
            <span className="font-mono text-[10.5px] sm:text-[11px] font-extrabold uppercase tracking-wider text-[#831C91] mb-1.5 block">
              WHY THIS MATTERS
            </span>
            <p className="text-slate-800 font-medium leading-relaxed font-sans">{whyThisMattersText}</p>
          </section>

          {/* 6. REMEDIATION STEPS */}
          <section>
            <span className="font-mono text-[10.5px] sm:text-[11px] font-extrabold uppercase tracking-wider text-[#462C7D] mb-2 block">
              REMEDIATION STEPS
            </span>

            <div className="space-y-1.5">
              {remediationSteps.map((step, idx) => {
                const numStr = String(idx + 1).padStart(2, '0');
                const textWithoutNum =
                  typeof step === 'string' ? step.replace(/^\d+\.\s*/, '') : String(step);

                return (
                  <div key={idx} className="flex items-start gap-2.5 sm:gap-3 py-1 text-slate-800">
                    <span className="font-mono text-[11px] font-extrabold text-[#831C91] shrink-0 pt-0.5">
                      {numStr}
                    </span>
                    <span className="text-[13px] sm:text-[13.5px] font-medium leading-relaxed flex-1">
                      {textWithoutNum}
                    </span>
                  </div>
                );
              })}
            </div>
          </section>
        </div>

        {/* Footer */}
        <div className="pt-3 sm:pt-4 mt-3 sm:mt-5 border-t border-[#462C7D]/20 flex flex-col-reverse sm:flex-row items-stretch sm:items-center justify-end gap-2 sm:gap-3 shrink-0">
          {/* Mark as resolved ghost button */}
          <button
            onClick={handleSmoothClose}
            className="px-4 py-2 rounded-xl text-xs font-bold text-[#462C7D] bg-white border border-[#462C7D]/30 hover:bg-[#462C7D]/10 transition-all cursor-pointer shadow-2xs text-center"
          >
            Mark as resolved
          </button>

          {/* Resolve filled button */}
          {isResolved ? (
            <button
              disabled
              className="px-5 py-2 rounded-xl text-xs font-bold text-emerald-800 bg-emerald-100/90 border border-emerald-300 opacity-90 cursor-not-allowed text-center"
            >
              Resolved ✓
            </button>
          ) : (
            <button
              disabled={isWorking || isClosing}
              onClick={handleResolveClick}
              className="px-5 py-2 rounded-xl text-xs font-bold text-white bg-gradient-to-r from-[#462C7D] via-[#831C91] to-[#D552A3] hover:brightness-110 shadow-md transition-all cursor-pointer text-center disabled:opacity-60"
            >
              {isWorking ? 'Resolving...' : 'Resolve'}
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
