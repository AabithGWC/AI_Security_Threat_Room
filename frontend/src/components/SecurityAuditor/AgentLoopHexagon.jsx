import React from 'react';
import {
  Terminal,
  ShieldAlert,
  Key,
  KeyRound,
  Activity,
  FileCode,
  CpuIcon,
} from 'lucide-react';
import { normalizeThreat, matchesThreatId } from '../../data/securityThreats';

export default function AgentLoopHexagon({
  activeStage,
  nodeStatuses,
  isAuditComplete,
  threats = [],
  onSelectThreat,
}) {
  const stages = [
    {
      id: 1,
      name: 'Discovery',
      icon: Terminal,
      defaultThreatId: 'prompt-injection',
      vulnerabilityTitle: 'Prompt Injection',
    },
    {
      id: 2,
      name: 'Threat Model',
      icon: ShieldAlert,
      defaultThreatId: 'no-delete-tool-guard',
      vulnerabilityTitle: 'No Delete Guard',
    },
    {
      id: 3,
      name: 'Vector Analysis',
      icon: Key,
      defaultThreatId: 'endpoint-authentication',
      vulnerabilityTitle: 'No Endpoint Auth',
    },
    {
      id: 4,
      name: 'Remediation',
      icon: KeyRound,
      defaultThreatId: 'secret-token-leakage',
      vulnerabilityTitle: 'Token Leakage',
    },
    {
      id: 5,
      name: 'Patch Verify',
      icon: Activity,
      defaultThreatId: 'rate-limiting',
      vulnerabilityTitle: 'No Rate Limit',
    },
    {
      id: 6,
      name: 'Report',
      icon: FileCode,
      defaultThreatId: 'env-git-commit',
      vulnerabilityTitle: '.env Git Risk',
    },
  ];

  const nodeThreatMapping = {
    1: ['prompt_injection', 'prompt-injection'],
    2: ['delete_no_guard', 'no-delete-tool-guard'],
    3: ['no_endpoint_auth', 'endpoint-authentication'],
    4: ['token_leakage', 'secret-token-leakage'],
    5: ['no_rate_limit', 'rate-limiting'],
    6: ['env_commit_risk', 'env-git-commit'],
  };

  // Helper to resolve mapped threat for a stage node
  const getMappedThreat = (stageId, defaultThreatId) => {
    if (!threats || threats.length === 0) return null;

    // 1. Direct stageId association
    let found = threats.find((t) => t.stageId === stageId);

    // 2. Target key / alias / title matching
    if (!found) {
      const targetKeys = nodeThreatMapping[stageId] || [];
      found = threats.find((t) =>
        targetKeys.some(
          (k) =>
            matchesThreatId(t.id, k) ||
            (t.alias && matchesThreatId(t.alias, k)) ||
            matchesThreatId(t.id, defaultThreatId) ||
            (t.title && t.title.toLowerCase().includes(k.split('-')[0]))
        )
      );
    }

    // 3. Positional fallback
    if (!found && threats[stageId - 1]) {
      found = threats[stageId - 1];
    }

    if (!found && defaultThreatId) {
      found = normalizeThreat({ id: defaultThreatId });
    }

    return found ? normalizeThreat(found) : null;
  };

  return (
    <div className="bg-[#FAF8FC] border border-[#462C7D]/20 rounded-2xl p-4.5 sm:p-5.5 px-5 sm:px-6 shadow-xs relative overflow-hidden transition-all duration-300 w-full">
      {/* CSS Keyframes for Active Node Glow & Rotating Ring */}
      <style>{`
        @keyframes auditPulse {
          0%, 100% {
            box-shadow: 0 0 0 0 rgba(142, 30, 158, 0.3);
          }
          50% {
            box-shadow: 0 0 0 8px rgba(142, 30, 158, 0.08);
          }
        }
        @keyframes auditRingSpin {
          0% { transform: rotate(0deg); }
          100% { transform: rotate(360deg); }
        }
        .animate-audit-pulse {
          animation: auditPulse 2s cubic-bezier(0.4, 0, 0.6, 1) infinite;
        }
        .animate-audit-ring {
          animation: auditRingSpin 2.2s linear infinite;
        }
      `}</style>

      {/* Section Header */}
      <div className="flex items-center justify-between mb-4 sm:mb-4.5 relative z-10">
        <div className="flex items-center gap-2.5">
          <div className="w-7 h-7 rounded-xl bg-gradient-to-br from-[#4C2882] to-[#8E1E9E] text-white flex items-center justify-center shadow-xs">
            <CpuIcon className="w-4 h-4 text-white" />
          </div>
          <h4 className="text-xs font-extrabold uppercase tracking-wider text-[#3C1F73] font-mono">
            AI AUDITOR ANALYSIS ENGINE
          </h4>
        </div>
      </div>

      {/* 6 Engine Nodes Grid — Single Row on Desktop */}
      <div className="relative z-10 grid grid-cols-2 sm:grid-cols-3 md:grid-cols-6 gap-3 sm:gap-4 items-center w-full py-0.5">
        {stages.map((stage) => {
          const Icon = stage.icon;
          const status = nodeStatuses
            ? nodeStatuses[stage.id] || 'pending'
            : activeStage > stage.id
            ? 'completed'
            : activeStage === stage.id
            ? 'running'
            : 'pending';

          const isActive = status === 'running';
          const isDone = status === 'completed';
          const mappedThreat = getMappedThreat(stage.id, stage.defaultThreatId);

          return (
            <div
              key={stage.id}
              className="relative flex flex-col items-center text-center group z-10 transition-all duration-200 select-none w-full"
            >
              {/* Node Icon Container Wrapper */}
              <div className="relative flex items-center justify-center">
                {/* Rotating Ring around Active Node */}
                {isActive && (
                  <div className="absolute -inset-1.5 rounded-full border-2 border-dashed border-[#8E1E9E] animate-audit-ring pointer-events-none z-0 opacity-90" />
                )}

                {/* Compact Clickable Vulnerability Action Icon Button */}
                <button
                  onClick={(e) => {
                    e.stopPropagation();
                    if (mappedThreat && onSelectThreat) {
                      onSelectThreat(mappedThreat);
                    }
                  }}
                  className={`relative z-10 w-11 h-11 sm:w-12 sm:h-12 rounded-full flex items-center justify-center transition-all duration-200 shadow-2xs group/iconbtn cursor-pointer ${
                    isActive
                      ? 'bg-white border-2 border-[#8E1E9E] text-[#8E1E9E] scale-105 animate-audit-pulse shadow-md'
                      : isDone || isAuditComplete
                      ? 'bg-white border-2 border-[#8E1E9E] text-[#5B2896] hover:scale-110 hover:shadow-md hover:border-[#3C1F73]'
                      : 'bg-white border border-[#4C2882]/35 text-[#4C2882]/85 hover:border-[#8E1E9E] hover:text-[#8E1E9E]'
                  }`}
                  title={mappedThreat ? `Click to view ${mappedThreat.title} details` : stage.name}
                >
                  <Icon className={`w-5 h-5 transition-transform group-hover/iconbtn:scale-110 stroke-[2.2] ${isActive ? 'animate-pulse' : ''}`} />
                </button>
              </div>

              {/* Stage Title Label */}
              <span
                className={`text-xs font-mono leading-tight mt-2 transition-all ${
                  isActive
                    ? 'font-extrabold text-[#8E1E9E]'
                    : isDone
                    ? 'font-extrabold text-[#3C1F73]'
                    : 'font-bold text-[#4C2882]/90'
                }`}
              >
                {stage.name}
              </span>

              {/* Status Indicator */}
              <div className="mt-0.5 flex flex-col items-center">
                {isActive ? (
                  <span className="text-[#8E1E9E] font-extrabold text-[10.5px] font-mono">Analyzing...</span>
                ) : isDone ? (
                  <span className="text-emerald-700 font-extrabold text-[10.5px] font-mono">Complete</span>
                ) : (
                  <span className="text-slate-500 font-bold text-[10.5px] font-mono">Pending</span>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
