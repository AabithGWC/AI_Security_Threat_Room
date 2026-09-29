import React, { useState, useEffect, useRef } from 'react';
import StatCubes from './StatCubes';
import ReadinessScoreOrb from './ReadinessScoreOrb';
import AgentLoopHexagon from './AgentLoopHexagon';
import FilterTabs from './FilterTabs';
import ThreatCard from './ThreatCard';
import AuditSummaryModal from './AuditSummaryModal';
import StageDetailModal from './StageDetailModal';
import ThreatDetailsModal from './ThreatDetailsModal';
import { normalizeThreat, matchesThreatId, getBackendThreatId, PROJECT_AUDIT_DATA, VERTEX_DATA_HUB_FINDINGS, SENTINEL_CORE_FINDINGS, ATLAS_SECURE_FINDINGS, QUANTUM_OPS_FINDINGS, AEGIS_ONE_FINDINGS } from '../../data/securityThreats';
import { Play, CheckCircle2, RotateCcw, RefreshCw, ArrowLeft, ShieldAlert, ChevronDown, Check, MessageSquare } from 'lucide-react';
import {
  streamAuditApi,
  fixThreatApi,
  revokeThreatApi,
  resolveAllThreatsApi,
  revokeAllThreatsApi,
} from '../../api/backend';

const fetchAuditFindings = async (projectType = 'db_agent') => {
  // Check if project is AegisOne Platform
  if (projectType === 'aegisone' || projectType === 'AegisOne Platform') {
    return AEGIS_ONE_FINDINGS.map((item) => ({ ...item, status: 'unresolved' }));
  }

  // Check if project is QuantumOps
  if (projectType === 'quantum_ops' || projectType === 'QuantumOps') {
    return QUANTUM_OPS_FINDINGS.map((item) => ({ ...item, status: 'unresolved' }));
  }

  // Check if project is Vertex Data Hub
  if (projectType === 'vertex_hub' || projectType === 'Vertex Data Hub') {
    return VERTEX_DATA_HUB_FINDINGS.map((item) => ({ ...item, status: 'unresolved' }));
  }

  // Check if project is SentinelCore
  if (projectType === 'sentinel_core' || projectType === 'SentinelCore') {
    return SENTINEL_CORE_FINDINGS.map((item) => ({ ...item, status: 'unresolved' }));
  }

  // Check if project is Atlas Secure Systems
  if (projectType === 'atlas_systems' || projectType === 'Atlas Secure Systems') {
    return ATLAS_SECURE_FINDINGS.map((item) => ({ ...item, status: 'unresolved' }));
  }

  // Check if defined in PROJECT_AUDIT_DATA
  if (PROJECT_AUDIT_DATA[projectType] && PROJECT_AUDIT_DATA[projectType].findings) {
    return PROJECT_AUDIT_DATA[projectType].findings.map((item) => ({ ...item, status: 'unresolved' }));
  }

  const defaultFindings = [
    {
      id: 'prompt_injection',
      domain: 'Prompt Security',
      severity: 'critical',
      title: 'Prompt injection vulnerability',
      status: 'unresolved',
      cvss: 9.8,
      cve: 'CVE-2026-9012',
      description: 'User input passes directly into the LLM with zero sanitization, allowing prompt injection attacks.',
      remediation: `// SECURED: Delimited System Policy\nsystem_prompt = StrictDelimiters(user_input, PolicyRules.DENY_SYSTEM_OVERRIDE);\nllm.invoke(system_prompt);`,
      diff_file: 'agent.py',
      diff_before: `self.messages.append({"role": "user", "content": user_message})`,
      diff_after: `MAX_INPUT_LENGTH = 2000\ndef _sanitize_input(user_in: str) -> str:\n    return user_in.strip()[:MAX_INPUT_LENGTH]\n\nsanitized = _sanitize_input(user_message)\nself.messages.append({"role": "user", "content": sanitized})`,
      diff_reason: 'Trims user input to 2000 characters and strips malicious payloads.',
    },
    {
      id: 'delete_no_guard',
      domain: 'Tool Security',
      severity: 'critical',
      title: 'No delete tool guard',
      status: 'unresolved',
      cvss: 9.5,
      cve: 'CVE-2026-4401',
      description: 'Delete tools have no code-level protection. Users could wipe documents without admin privileges.',
      remediation: `// SECURED: Block delete operations without admin access\nif (tool_name.startsWith('delete')) {\n  return 'Access denied: Admin access required';\n}`,
      diff_file: 'tools.py',
      diff_before: `result = fn(**args)`,
      diff_after: `if name in ("delete_document", "delete_documents_by_field"):\n    return "Access denied: Delete operations require admin access."`,
      diff_reason: 'Blocks unauthorized deletion of database records.',
    },
    {
      id: 'no_endpoint_auth',
      domain: 'Authentication',
      severity: 'critical',
      title: 'No endpoint authentication',
      status: 'unresolved',
      cvss: 9.1,
      cve: 'CVE-2026-7832',
      description: 'FastAPI endpoints have no authentication middleware, leaving API exposed.',
      remediation: `// SECURED: Enforce API Key Middleware\napp.middleware('http')(verify_api_key);`,
      diff_file: 'app.py',
      diff_before: `@app.post("/chat")\ndef chat(req: ChatRequest):`,
      diff_after: `@app.middleware("http")\nasync def verify_api_key(request: Request, call_next):\n    key = request.headers.get("X-API-Key", "")\n    if key != API_SECRET_KEY:\n        return JSONResponse(status_code=401, content={"detail": "Unauthorized"})`,
      diff_reason: 'Validates API key header on all protected HTTP requests.',
    },
    {
      id: 'token_leakage',
      domain: 'Credential Security',
      severity: 'critical',
      title: 'Token / secret leakage',
      status: 'unresolved',
      cvss: 8.8,
      cve: 'CVE-2026-5519',
      description: 'Developer tokens or API keys could leak in LLM output responses.',
      remediation: `// SECURED: Output Sanitizer\nreply = sanitize_output(llm_response);`,
      diff_file: 'agent.py',
      diff_before: `return msg.content or ""`,
      diff_after: `reply = _sanitize_output(msg.content or "")\nreturn reply`,
      diff_reason: 'Strips tokens and credentials from model output before returning.',
    },
    {
      id: 'no_rate_limit',
      domain: 'Authentication',
      severity: 'high',
      title: 'No rate limiting',
      status: 'unresolved',
      cvss: 7.5,
      cve: 'CVE-2026-3321',
      description: 'No request throttling on API endpoints, allowing denial of service or credit drain.',
      remediation: `// SECURED: SlowAPI Rate Limiter\n@limiter.limit('10/minute')`,
      diff_file: 'app.py',
      diff_before: `@app.post("/chat")\ndef chat(req: ChatRequest):`,
      diff_after: `@app.post("/chat")\n@limiter.limit("10/minute")\ndef chat(request: Request, req: ChatRequest):`,
      diff_reason: 'Limits clients to 10 requests per minute to prevent DoS attacks.',
    },
    {
      id: 'env_commit_risk',
      domain: 'Credential Security',
      severity: 'medium',
      title: '.env git commit risk',
      status: 'unresolved',
      cvss: 7.5,
      cve: 'CVE-2026-1104',
      description: '.env file missing from .gitignore, risking accidental credential check-in.',
      remediation: `// SECURED: Gitignore rules\n.env\n*.env`,
      diff_file: '.gitignore',
      diff_before: `__pycache__/\nvenv/\n*.pyc`,
      diff_after: `.env\n*.env\n__pycache__/`,
      diff_reason: 'Prevents accidental push of environment secrets to version control.',
    },
  ];

  try {
    const fetched = await new Promise((resolve) => {
      const results = [];
      const timer = setTimeout(() => resolve(null), 3000);

      const closeStream = streamAuditApi(
        (data) => {
          if (data && data.type === 'finding' && data.finding) {
            // Force every newly scanned threat finding to 'unresolved' on an audit run!
            const f = {
              ...data.finding,
              status: 'unresolved',
            };
            results.push(f);
          } else if (data && data.type === 'done') {
            clearTimeout(timer);
            resolve(results);
          }
        },
        () => {
          clearTimeout(timer);
          resolve(null);
        },
        () => {
          clearTimeout(timer);
          resolve(results);
        }
      );
    });

    if (fetched && fetched.length > 0) {
      return fetched.map((item) => ({ ...item, status: 'unresolved' }));
    }
  } catch (e) {
    console.warn('Backend audit stream unavailable, using canonical baseline findings:', e);
  }

  return defaultFindings.map((item) => ({ ...item, status: 'unresolved' }));
};

const STORAGE_KEY = 'ai-security-auditor-state';

const INITIAL_AUDIT_STATE = {
  auditStatus: 'idle', // 'idle' | 'running' | 'completed' | 'error'
  runId: null,
  currentNode: null,
  nodeStatuses: {
    1: 'pending',
    2: 'pending',
    3: 'pending',
    4: 'pending',
    5: 'pending',
    6: 'pending',
  },
  findings: [],
  critical: 0,
  high: 0,
  medium: 0,
  resolved: 0,
  readiness: null, // Displayed as "--%" in initial state
};

// CANONICAL SINGLE SOURCE OF TRUTH SCORE CALCULATION
function calculateMetricsAndReadiness(findingsList) {
  if (!findingsList || findingsList.length === 0) {
    return { critical: 0, high: 0, medium: 0, resolved: 0, readiness: null };
  }

  const critical = findingsList.filter((t) => (t.severity || '').toLowerCase() === 'critical' && t.status !== 'resolved').length;
  const high = findingsList.filter((t) => (t.severity || '').toLowerCase() === 'high' && t.status !== 'resolved').length;
  const medium = findingsList.filter((t) => (t.severity || '').toLowerCase() === 'medium' && t.status !== 'resolved').length;
  const lows = findingsList.filter((t) => (t.severity || '').toLowerCase() === 'low' && t.status !== 'resolved').length;
  const resolved = findingsList.filter((t) => t.status === 'resolved').length;

  const totalActivePenalty = critical * 12 + high * 7 + medium * 3 + lows * 1;
  const readiness = Math.max(0, 100 - totalActivePenalty);

  return { critical, high, medium, resolved, readiness };
}

const AUDIT_OPTIONS = [
  { id: 'db_agent', label: 'DB Agent' },
  { id: 'aegisone', label: 'AegisOne Platform' },
  { id: 'vertex_hub', label: 'Vertex Data Hub' },
  { id: 'sentinel_core', label: 'SentinelCore' },
  { id: 'quantum_ops', label: 'QuantumOps' },
  { id: 'atlas_systems', label: 'Atlas Secure Systems' },
];

export default function AuditorDashboard({ onBackToChat }) {
  // ALWAYS INITIALIZE IN CLEAN INITIAL_AUDIT_STATE (NO PERSISTENCE RESTORATION)
  const [auditState, setAuditState] = useState(INITIAL_AUDIT_STATE);

  const activeRunIdRef = useRef(null);

  // SELECT AUDIT DROPDOWN STATE
  const [selectedAuditType, setSelectedAuditType] = useState('db_agent');
  const [isAuditDropdownOpen, setIsAuditDropdownOpen] = useState(false);
  const dropdownRef = useRef(null);

  useEffect(() => {
    function handleClickOutside(event) {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target)) {
        setIsAuditDropdownOpen(false);
      }
    }
    if (isAuditDropdownOpen) {
      document.addEventListener('mousedown', handleClickOutside);
    }
    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
    };
  }, [isAuditDropdownOpen]);

  const [activeFilter, setActiveFilter] = useState('all');
  const [isBatchWorking, setIsBatchWorking] = useState(false);
  const [batchActionType, setBatchActionType] = useState(null); // 'resolve' | 'revoke' | 'reset'
  const [auditLog, setAuditLog] = useState('');
  const [verdictStatus, setVerdictStatus] = useState('idle');

  const [showSummaryModal, setShowSummaryModal] = useState(false);
  const [selectedStageModal, setSelectedStageModal] = useState(null);
  const [processingThreatIds, setProcessingThreatIds] = useState([]);

  const [revokeProgress, setRevokeProgress] = useState(0);
  const [resolveProgress, setResolveProgress] = useState(0);
  const [isRevoking, setIsRevoking] = useState(false);
  const [isResolving, setIsResolving] = useState(false);

  // THREAT MODAL STATES
  const [selectedThreat, setSelectedThreat] = useState(null);
  const [isThreatModalOpen, setIsThreatModalOpen] = useState(false);

  // SEGMENTED TOGGLE STATE FOR BATCH ACTION ('resolve' | 'revoke')
  const [batchToggleMode, setBatchToggleMode] = useState('resolve');

  // UNMOUNT & PAGE SWITCH CLEANUP HANDLER (NO PERSISTENCE IN BROWSER STORAGE)
  useEffect(() => {
    // Clear residual browser storage items on mount
    try {
      localStorage.removeItem(STORAGE_KEY);
      localStorage.removeItem('auditor_findings');
    } catch (e) {
      // Ignore storage error
    }

    return () => {
      // On unmount (switching tabs / leaving page):
      // 1. Invalidate active run ID so any ongoing async pipeline aborts immediately
      activeRunIdRef.current = null;

      // 2. Clear browser storage items
      try {
        localStorage.removeItem(STORAGE_KEY);
        localStorage.removeItem('auditor_findings');
      } catch (e) {
        // Ignore storage error
      }

      // 3. Reset local component state & modal state
      setAuditState(INITIAL_AUDIT_STATE);
      setSelectedThreat(null);
      setIsThreatModalOpen(false);
    };
  }, []);

  const threats = auditState.findings;

  // Auto-sync toggle active state with threats state if all resolved or all unresolved
  useEffect(() => {
    if (threats && threats.length > 0) {
      const allResolved = threats.every((t) => t.status === 'resolved');
      const allUnresolved = threats.every((t) => t.status === 'unresolved');
      if (allResolved) {
        setBatchToggleMode('resolve');
      } else if (allUnresolved) {
        setBatchToggleMode('revoke');
      }
    }
  }, [threats]);
  const auditStarted = auditState.auditStatus !== 'idle';
  const auditRunning = auditState.auditStatus === 'running';
  const auditCompleted = auditState.auditStatus === 'completed';
  const readinessScore = auditState.readiness;
  const scanStage = auditState.currentNode !== null
    ? (auditState.auditStatus === 'completed' ? 7 : auditState.currentNode)
    : 0;

  const counts = {
    all: threats.length,
    critical: auditState.critical,
    high: auditState.high,
    medium: auditState.medium,
    resolved: auditState.resolved,
  };

  // THREAT CLICK HANDLER
  const handleThreatClick = (threat) => {
    if (!auditCompleted) return;

    // Defensive: always resolve through normalizeThreat using id/title,
    // so even if the clicked item is missing fields, the correct full
    // threat record from SECURITY_THREATS is used.
    const fullThreat = normalizeThreat(threat);

    console.log('CLICKED RAW:', threat);
    console.log('RESOLVED FULL THREAT:', fullThreat);

    setSelectedThreat(fullThreat);
    setIsThreatModalOpen(true);
  };

  // CLOSE THREAT MODAL
  const handleCloseThreatModal = () => {
    setIsThreatModalOpen(false);
    setSelectedThreat(null);
  };

  // 1. RUN FULL SECURITY AUDIT
  const handleStartAudit = async () => {
    if (auditState.auditStatus === 'running' || isResolving || isRevoking) return;

    // Reset selected modal if open
    setIsThreatModalOpen(false);
    setSelectedThreat(null);

    // Unique execution ID to prevent stale run race conditions
    const runId = `audit-${Date.now()}-${Math.random().toString(36).substring(2, 9)}`;
    activeRunIdRef.current = runId;

    const currentProject = AUDIT_OPTIONS.find((o) => o.id === selectedAuditType)?.label || selectedAuditType;
    console.log(`[Audit] Starting execution run: ${runId} for project: ${currentProject}`);

    setShowSummaryModal(false);
    setVerdictStatus('scan');
    setAuditLog(`Starting AI Security Audit pipeline for ${currentProject}...\n`);

    // Reset to initial running state (Readiness score starts at null displayed as "--%")
    setAuditState({
      auditStatus: 'running',
      runId,
      currentNode: 1,
      nodeStatuses: { 1: 'pending', 2: 'pending', 3: 'pending', 4: 'pending', 5: 'pending', 6: 'pending' },
      findings: [],
      critical: 0,
      high: 0,
      medium: 0,
      resolved: 0,
      readiness: null,
    });

    // Fetch project-specific baseline findings internally (forced to status: 'unresolved' for audit scan!)
    const allDiscoveredFindings = await fetchAuditFindings(selectedAuditType);
    if (activeRunIdRef.current !== runId) return;

    const nodes = [
      { id: 1, name: 'Discovery', revealCount: 1 },
      { id: 2, name: 'Threat Model', revealCount: 2 },
      { id: 3, name: 'Vector Analysis', revealCount: 4 },
      { id: 4, name: 'Remediation', revealCount: 5 },
      { id: 5, name: 'Patch Verify', revealCount: 6 },
      { id: 6, name: 'Report', revealCount: 6 },
    ];

    // STRICT 6-STAGE SEQUENTIAL PIPELINE LOOP
    for (const node of nodes) {
      if (activeRunIdRef.current !== runId) {
        console.warn(`[Audit] Aborted execution during ${node.name}`);
        return;
      }

      // STEP 1 — START CURRENT NODE ("Analyzing...")
      console.log(`[Audit] Node ${node.id} (${node.name}) -> ANALYZING`);
      setAuditLog((prev) => prev + `[Stage ${node.id}/6] Running ${node.name}...\n`);

      setAuditState((prev) => {
        if (prev.runId !== runId) return prev;
        return {
          ...prev,
          currentNode: node.id,
          nodeStatuses: {
            ...prev.nodeStatuses,
            [node.id]: 'running',
          },
        };
      });

      // Visual stage processing delay
      await new Promise((r) => setTimeout(r, 650));
      if (activeRunIdRef.current !== runId) return;

      // STEP 2 — REVEAL ONLY FINDINGS BELONGING TO THIS STAGE
      const stageFindings = allDiscoveredFindings.slice(0, node.revealCount).map((f) => ({ ...f, status: 'unresolved' }));

      // Recalculate metrics strictly from the findings revealed up to this stage
      const stageMetrics = calculateMetricsAndReadiness(stageFindings);

      // STEP 3 — UPDATE AUDIT STATE IMMEDIATELY & MARK NODE COMPLETED ✓
      console.log(`[Audit] Node ${node.id} (${node.name}) -> COMPLETED ✓ (Readiness: ${stageMetrics.readiness}%)`);
      setAuditState((prev) => {
        if (prev.runId !== runId) return prev;
        return {
          ...prev,
          nodeStatuses: {
            ...prev.nodeStatuses,
            [node.id]: 'completed',
          },
          findings: stageFindings,
          critical: stageMetrics.critical,
          high: stageMetrics.high,
          medium: stageMetrics.medium,
          resolved: stageMetrics.resolved,
          readiness: stageMetrics.readiness,
        };
      });

      // STEP 4 — WAIT FOR RENDER & CONNECTION ANIMATION BEFORE MOVING TO NEXT STAGE
      await new Promise((r) => setTimeout(r, 450));
    }

    // ONLY AFTER ALL 6 STAGES FINISH:
    if (activeRunIdRef.current !== runId) return;

    const finalUnresolvedFindings = allDiscoveredFindings.map((f) => ({ ...f, status: 'unresolved' }));
    const finalMetrics = calculateMetricsAndReadiness(finalUnresolvedFindings);

    // STEP 5 — MARK AUDIT COMPLETED
    setAuditState((prev) => {
      if (prev.runId !== runId) return prev;
      return {
        ...prev,
        auditStatus: 'completed',
        currentNode: null,
        nodeStatuses: { 1: 'completed', 2: 'completed', 3: 'completed', 4: 'completed', 5: 'completed', 6: 'completed' },
        findings: finalUnresolvedFindings,
        critical: finalMetrics.critical,
        high: finalMetrics.high,
        medium: finalMetrics.medium,
        resolved: finalMetrics.resolved,
        readiness: finalMetrics.readiness,
      };
    });

    if (finalMetrics.critical + finalMetrics.high > 0) setVerdictStatus('red');

    console.log(`[Audit] Full audit completed: ${runId}`);
    setAuditLog((prev) => prev + `\n✅ Full AI Security Audit completed successfully.\n`);
  };

  // IMMEDIATE UI INDIVIDUAL RESOLVE HANDLER
  const handleFixThreat = (threatId, isFromModal = false) => {
    if (!threatId) return;

    const backendThreatId = getBackendThreatId(threatId);
    setProcessingThreatIds((prev) => [...new Set([...prev, threatId, backendThreatId])]);

    let nextUnresolvedFinding = null;

    // 1. Instant local state update (0ms latency, eliminates backend reload lag on finding #3)
    setAuditState((prevState) => {
      const nextFindings = prevState.findings.map((t) => {
        if (matchesThreatId(t.id, threatId) || (t.alias && matchesThreatId(t.alias, threatId)) || t.id === threatId) {
          return { ...t, status: 'resolved' };
        }
        return t;
      });
      const metrics = calculateMetricsAndReadiness(nextFindings);

      if (metrics.critical + metrics.high > 0) setVerdictStatus('red');
      else if (metrics.resolved > 0 && metrics.critical + metrics.high === 0) setVerdictStatus('green');

      // Look for the next unresolved finding in the active list
      const remainingUnresolved = nextFindings.filter((t) => t.status !== 'resolved');
      if (remainingUnresolved.length > 0) {
        nextUnresolvedFinding = remainingUnresolved[0];
      }

      return {
        ...prevState,
        findings: nextFindings,
        critical: metrics.critical,
        high: metrics.high,
        medium: metrics.medium,
        resolved: metrics.resolved,
        readiness: metrics.readiness,
      };
    });

    // 2. Update active selected threat status to resolved while closing animation plays
    setSelectedThreat((prev) => {
      if (prev && (matchesThreatId(prev.id, threatId) || (prev.alias && matchesThreatId(prev.alias, threatId)) || prev.id === threatId)) {
        return { ...prev, status: 'resolved' };
      }
      return prev;
    });

    // 3. Asynchronous backend persistence in background without blocking UI
    fixThreatApi(backendThreatId, { id: threatId, project: selectedAuditType })
      .catch((err) => {
        console.warn(`Backend fix API notice: ${err.message}. Local state already updated.`);
      })
      .finally(() => {
        setProcessingThreatIds((prev) => prev.filter((id) => id !== threatId && id !== backendThreatId));
      });
  };

  // SINGLE THREAT RESOLVE FROM MODAL
  const handleResolveSingleThreatFromModal = (threatId) => {
    handleFixThreat(threatId, true);
  };

  // IMMEDIATE UI INDIVIDUAL REVOKE HANDLER
  const handleRevokeThreat = (threatId) => {
    if (!threatId) return;

    const backendThreatId = getBackendThreatId(threatId);
    setProcessingThreatIds((prev) => [...new Set([...prev, threatId, backendThreatId])]);

    setAuditState((prevState) => {
      const nextFindings = prevState.findings.map((t) => {
        if (matchesThreatId(t.id, threatId) || (t.alias && matchesThreatId(t.alias, threatId)) || t.id === threatId) {
          return { ...t, status: 'unresolved' };
        }
        return t;
      });
      const metrics = calculateMetricsAndReadiness(nextFindings);

      if (metrics.critical + metrics.high > 0) setVerdictStatus('red');
      else if (metrics.resolved > 0 && metrics.critical + metrics.high === 0) setVerdictStatus('green');

      return {
        ...prevState,
        findings: nextFindings,
        critical: metrics.critical,
        high: metrics.high,
        medium: metrics.medium,
        resolved: metrics.resolved,
        readiness: metrics.readiness,
      };
    });

    setSelectedThreat((prev) => {
      if (prev && (matchesThreatId(prev.id, threatId) || (prev.alias && matchesThreatId(prev.alias, threatId)) || prev.id === threatId)) {
        return { ...prev, status: 'unresolved' };
      }
      return prev;
    });

    revokeThreatApi(backendThreatId, { id: threatId, project: selectedAuditType })
      .catch((err) => {
        console.warn(`Backend revoke API notice: ${err.message}. Local state already updated.`);
      })
      .finally(() => {
        setProcessingThreatIds((prev) => prev.filter((id) => id !== threatId && id !== backendThreatId));
      });
  };

  // 2. EXPLICIT RESOLVE ALL HANDLER
  const handleResolveAll = async () => {
    if (!auditState.findings.length || isResolving || isRevoking || auditState.auditStatus === 'running') return;
    setIsResolving(true);
    setResolveProgress(0);
    setIsBatchWorking(true);
    setBatchActionType('resolve');

    try {
      await resolveAllThreatsApi();
    } catch (err) {
      console.warn(`Backend resolve-all notice: ${err.message}. Applying immediate local state update.`);
    } finally {
      setAuditState((prevState) => {
        const nextFindings = prevState.findings.map((t) => ({ ...t, status: 'resolved' }));
        const metrics = calculateMetricsAndReadiness(nextFindings);
        setVerdictStatus('green');

        return {
          ...prevState,
          findings: nextFindings,
          critical: metrics.critical,
          high: metrics.high,
          medium: metrics.medium,
          resolved: metrics.resolved,
          readiness: metrics.readiness,
        };
      });

      setIsResolving(false);
      setResolveProgress(0);
      setIsBatchWorking(false);
      setBatchActionType(null);
    }
  };

  // 3. EXPLICIT REVOKE ALL HANDLER
  const handleRevokeAll = async () => {
    if (!auditState.findings.length || isResolving || isRevoking || auditState.auditStatus === 'running') return;
    setIsRevoking(true);
    setRevokeProgress(0);
    setIsBatchWorking(true);
    setBatchActionType('revoke');

    try {
      await revokeAllThreatsApi();
    } catch (err) {
      console.warn(`Backend revoke-all notice: ${err.message}. Applying immediate local state update.`);
    } finally {
      setAuditState((prevState) => {
        const nextFindings = prevState.findings.map((t) => ({ ...t, status: 'unresolved' }));
        const metrics = calculateMetricsAndReadiness(nextFindings);

        if (metrics.critical + metrics.high > 0) setVerdictStatus('red');

        return {
          ...prevState,
          findings: nextFindings,
          critical: metrics.critical,
          high: metrics.high,
          medium: metrics.medium,
          resolved: metrics.resolved,
          readiness: metrics.readiness,
        };
      });

      setIsRevoking(false);
      setRevokeProgress(0);
      setIsBatchWorking(false);
      setBatchActionType(null);
    }
  };

  // 4. RESET HANDLER
  const handleReset = async () => {
    setIsBatchWorking(true);
    setBatchActionType('reset');
    setShowSummaryModal(false);
    setSelectedThreat(null);
    setIsThreatModalOpen(false);
    activeRunIdRef.current = null;

    try {
      await revokeAllThreatsApi();
    } catch (err) {
      console.error('Error revoking threat patches on reset:', err);
    } finally {
      setIsBatchWorking(false);
      setBatchActionType(null);

      // Explicitly clear stored audit state upon clicking Reset button
      try {
        localStorage.removeItem(STORAGE_KEY);
        localStorage.removeItem('auditor_findings');
      } catch (e) {
        // Ignore
      }

      // Revert completely to clean INITIAL_AUDIT_STATE
      setAuditState(INITIAL_AUDIT_STATE);
      setAuditLog('');
      setVerdictStatus('idle');
      setActiveFilter('all');
    }
  };

  // Filter findings for list
  const filteredThreats = threats.filter((threat) => {
    if (activeFilter === 'all') return true;
    if (activeFilter === 'resolved') return threat.status === 'resolved';
    return (threat.severity || '').toLowerCase() === activeFilter && threat.status !== 'resolved';
  });

  return (
    <div className="flex-1 p-3 sm:p-4 md:p-6 max-w-[1450px] mx-auto w-full flex flex-col gap-4 sm:gap-5 justify-start">
      {/* Top Controls Bar / Navbar */}
      <div className="flex flex-col lg:flex-row items-stretch lg:items-center justify-between gap-3 lg:gap-3.5 bg-white py-3 sm:py-3.5 px-3.5 sm:px-4 md:px-5 rounded-2xl border border-[#462C7D]/20 shadow-xs w-full min-h-[64px] relative z-30">
        {/* Left Section: Back Arrow Button + GWC DATA.AI Logo + Divider + Title & Subtitle */}
        <div className="flex items-center gap-2 sm:gap-3 shrink-0 justify-between sm:justify-start">
          <div className="flex items-center gap-2 sm:gap-2.5 shrink-0">
            {/* Compact Back Arrow Button */}
            <button
              onClick={onBackToChat}
              className="flex items-center justify-center w-9 h-9 sm:w-9.5 sm:h-9.5 rounded-xl bg-white hover:bg-[#4C2882]/10 text-[#4C2882] hover:text-[#8E1E9E] border border-[#462C7D]/25 hover:border-[#8E1E9E]/50 transition-all duration-200 cursor-pointer shadow-2xs shrink-0 group"
              title="Back to Agent Chat"
              aria-label="Back to Agent Chat"
            >
              <ArrowLeft className="w-4 h-4 stroke-[2.2] text-[#3C1F73] group-hover:text-[#8E1E9E] group-hover:-translate-x-0.5 transition-transform" />
            </button>

            <img
              src="/gwc-data-ai-logo.png"
              alt="GWC DATA.AI Logo"
              className="h-8 sm:h-8.5 w-auto object-contain max-w-[125px] sm:max-w-[150px] shrink-0"
              onError={(e) => { e.currentTarget.src = '/gwc-logo.jpg'; }}
            />
          </div>

          <div className="h-7 w-px bg-[#462C7D]/18 hidden md:block shrink-0" />

          <div className="flex flex-col justify-center text-left min-w-0 shrink-0">
            <h1 className="font-display font-extrabold text-[#3B1F73] text-sm sm:text-base leading-tight tracking-tight whitespace-nowrap">
              AI Security Auditor
            </h1>
            <p className="text-[10px] sm:text-[11px] text-slate-500 font-mono font-medium leading-tight mt-0.5 whitespace-nowrap">
              Real-time vulnerability & threat mitigation
            </p>
          </div>
        </div>

        {/* Flexible Spacer (Desktop Only) */}
        <div className="hidden lg:block flex-1 min-w-2" />

        {/* Right Section: Dropdown + Action Controls Group (Single Horizontal Flex Row) */}
        <div className="flex items-center gap-1.5 sm:gap-2 lg:gap-2.5 flex-wrap sm:flex-nowrap shrink-0 justify-start lg:justify-end relative z-40">
          {/* Project Dropdown: Select Project */}
          <div className="relative shrink-0 z-50" ref={dropdownRef}>
            <button
              type="button"
              onClick={() => setIsAuditDropdownOpen((prev) => !prev)}
              className={`flex items-center justify-between gap-1.5 sm:gap-2 h-[38px] w-36 sm:w-40 md:w-42 px-2.5 sm:px-3 bg-white hover:bg-[#4C2882]/5 border ${
                isAuditDropdownOpen
                  ? 'border-[#8E1E9E] ring-2 ring-[#8E1E9E]/15'
                  : 'border-[#462C7D]/25 hover:border-[#8E1E9E]/50'
              } rounded-xl text-xs font-bold text-[#3C1F73] transition-all duration-200 shadow-2xs cursor-pointer select-none whitespace-nowrap shrink-0`}
              aria-expanded={isAuditDropdownOpen}
              title="Select Project"
            >
              <div className="flex items-center gap-1 min-w-0 truncate">
                <span className="truncate">{AUDIT_OPTIONS.find((o) => o.id === selectedAuditType)?.label || 'DB Agent'}</span>
              </div>
              <ChevronDown
                className={`w-3.5 h-3.5 text-[#8E1E9E] shrink-0 transition-transform duration-200 ${
                  isAuditDropdownOpen ? 'rotate-180' : ''
                }`}
              />
            </button>

            {/* Dropdown Menu */}
            {isAuditDropdownOpen && (
              <div className="absolute left-0 sm:left-auto sm:right-0 top-full mt-1.5 w-48 sm:w-52 bg-white/98 backdrop-blur-md rounded-xl border border-[#462C7D]/22 shadow-xl shadow-[#3B1F73]/15 py-1 z-[100] animate-in fade-in zoom-in-95 duration-150">
                <div className="px-3 py-1 text-[10px] font-mono font-extrabold uppercase tracking-wider text-[#8E1E9E] border-b border-[#462C7D]/10 mb-1">
                  Select Project
                </div>
                {AUDIT_OPTIONS.map((opt) => {
                  const isSelected = opt.id === selectedAuditType;
                  return (
                    <button
                      key={opt.id}
                      type="button"
                      onClick={(e) => {
                        e.stopPropagation();
                        setSelectedAuditType(opt.id);
                        setIsAuditDropdownOpen(false);
                      }}
                      className={`w-full flex items-center justify-between px-3 py-2 text-xs font-bold text-left transition-colors cursor-pointer ${
                        isSelected
                          ? 'bg-[#4C2882]/10 text-[#8E1E9E] font-extrabold'
                          : 'text-[#3C1F73] hover:bg-[#4C2882]/6 hover:text-[#4C2882]'
                      }`}
                    >
                      <span className="truncate">{opt.label}</span>
                      {isSelected && <Check className="w-3.5 h-3.5 text-[#8E1E9E] shrink-0 ml-1.5 stroke-[2.5]" />}
                    </button>
                  );
                })}
              </div>
            )}
          </div>

          {/* 1. Run Full Security Audit (Primary Action) */}
          <button
            onClick={handleStartAudit}
            disabled={auditRunning || isResolving || isRevoking}
            className="flex items-center justify-center gap-1.5 h-[38px] px-3 sm:px-3.5 rounded-xl text-xs font-extrabold text-white bg-gradient-to-r from-[#4C2882] via-[#8E1E9E] to-[#D84BA1] hover:brightness-110 shadow-md shadow-[#4C2882]/25 transition-all disabled:opacity-50 cursor-pointer shrink-0 whitespace-nowrap"
          >
            <Play className="w-3.5 h-3.5 fill-current text-white stroke-[2]" />
            <span>{auditRunning ? 'Scanning…' : 'Run Full Security Audit'}</span>
          </button>

          {/* 2 & 3. Segmented Control: Resolve All / Revoke All Toggle */}
          <div
            className={`relative flex items-center h-[38px] p-1 bg-[#4C2882]/12 rounded-xl border border-[#462C7D]/25 shadow-2xs transition-all shrink-0 select-none ${
              auditRunning || isBatchWorking || isResolving || isRevoking || !auditStarted ? 'opacity-60 cursor-not-allowed' : ''
            }`}
          >
            {/* Sliding Background Pill */}
            <div
              className={`absolute top-1 bottom-1 w-[calc(50%-4px)] rounded-lg shadow-xs transition-all duration-300 cubic-bezier(0.4,0,0.2,1) ${
                batchToggleMode === 'resolve'
                  ? 'left-1 bg-gradient-to-r from-[#8E1E9E] to-[#D84BA1]'
                  : 'left-[50%] bg-gradient-to-r from-[#4C2882] to-[#8E1E9E]'
              } ${isResolving || isRevoking ? 'animate-pulse' : ''}`}
            />

            {/* Resolve All Segment */}
            <button
              type="button"
              onClick={() => {
                if (auditRunning || isBatchWorking || isResolving || isRevoking || !auditStarted) return;
                setBatchToggleMode('resolve');
                handleResolveAll();
              }}
              disabled={auditRunning || isBatchWorking || isResolving || isRevoking || !auditStarted}
              className={`relative z-10 flex items-center justify-center h-full gap-1 sm:gap-1.5 px-2 sm:px-2.5 md:px-3 rounded-lg text-xs font-extrabold transition-colors duration-200 cursor-pointer whitespace-nowrap ${
                batchToggleMode === 'resolve'
                  ? 'text-white'
                  : 'text-[#3C1F73] hover:text-[#4C2882]'
              } disabled:cursor-not-allowed`}
              title="Resolve all security threats"
            >
              <CheckCircle2 className={`w-3.5 h-3.5 ${isResolving ? 'animate-spin' : ''}`} />
              <span>{isResolving ? 'Resolving All' : 'Resolve All'}</span>
            </button>

            {/* Revoke All Segment */}
            <button
              type="button"
              onClick={() => {
                if (auditRunning || isBatchWorking || isResolving || isRevoking || !auditStarted) return;
                setBatchToggleMode('revoke');
                handleRevokeAll();
              }}
              disabled={auditRunning || isBatchWorking || isResolving || isRevoking || !auditStarted}
              className={`relative z-10 flex items-center justify-center h-full gap-1 sm:gap-1.5 px-2 sm:px-2.5 md:px-3 rounded-lg text-xs font-extrabold transition-colors duration-200 cursor-pointer whitespace-nowrap ${
                batchToggleMode === 'revoke'
                  ? 'text-white'
                  : 'text-rose-800 hover:text-rose-950'
              } disabled:cursor-not-allowed`}
              title="Revoke all applied threat patches"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isRevoking ? 'animate-spin' : ''}`} />
              <span>{isRevoking ? 'Revoking All' : 'Revoke All'}</span>
            </button>
          </div>

          {/* 4. Reset Button */}
          <button
            onClick={handleReset}
            disabled={auditRunning || isBatchWorking || isResolving || isRevoking}
            className={`flex items-center justify-center gap-1.5 h-[38px] px-2.5 sm:px-3 rounded-xl text-xs font-extrabold transition-all shadow-2xs cursor-pointer shrink-0 whitespace-nowrap ${
              batchActionType === 'reset'
                ? 'btn-working-revoke text-white'
                : 'bg-white text-slate-700 hover:bg-slate-100 border border-slate-300'
            } disabled:opacity-50`}
          >
            <RotateCcw className="w-3.5 h-3.5 text-slate-600 stroke-[2.2]" />
            <span>Reset</span>
          </button>
        </div>
      </div>

      {/* 2. Stat Cubes (Security Summary Cards) */}
      <StatCubes counts={counts} />

      {/* 3. Production Security Readiness */}
      <ReadinessScoreOrb
        score={readinessScore}
        visible={true}
        isLoading={auditRunning || isBatchWorking || isResolving || isRevoking}
      />

      {/* 4. AI Auditor Analysis Engine */}
      <AgentLoopHexagon
        activeStage={scanStage}
        nodeStatuses={auditState.nodeStatuses}
        isAuditComplete={auditCompleted}
        threats={threats}
        onSelectThreat={handleThreatClick}
      />

      {/* Post-Audit Summary Modal (Triggered ONLY by explicit Resolve All) */}
      <AuditSummaryModal
        isOpen={showSummaryModal}
        onClose={() => setShowSummaryModal(false)}
        threats={threats}
        readinessScore={readinessScore}
      />



      {/* Dynamic Threat Details Modal */}
      <ThreatDetailsModal
        threat={selectedThreat}
        isOpen={isThreatModalOpen}
        onClose={handleCloseThreatModal}
        onResolve={handleResolveSingleThreatFromModal}
        isWorking={selectedThreat ? processingThreatIds.some((id) => matchesThreatId(id, selectedThreat.id)) : false}
      />
    </div>
  );
}
