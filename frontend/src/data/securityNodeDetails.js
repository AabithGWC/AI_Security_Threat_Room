export const NODE_THREAT_DETAILS = {
  discovery: {
    id: 'discovery',
    title: 'Security Discovery',
    category: 'Threat Discovery',
    cvss: '9.8',
    severity: 'CRITICAL',
    description:
      'Scans application architecture, API endpoints, user inputs, permissions, authentication flows, secrets, and exposed attack surfaces.',
    attackScenario:
      'An attacker scans exposed application endpoints and unmapped user input routes to identify unauthenticated entry points and system boundaries.',
    businessImpact:
      'Unmapped attack surfaces increase the risk of undetected intrusions, data leakage, and unauthorized administrative endpoint access.',
    originalCode: `// BEFORE IMPLEMENTATION:
Unmapped application surface
Unknown API endpoints
Unverified user permissions
Exposed environment secrets`,
    patchedCode: `// AFTER SECURITY MITIGATION:
Application architecture mapped
Endpoints inventoried & cataloged
Permissions identified & scoped
Attack surface fully documented`,
    expectedChanges:
      'Map all application API endpoints, enforce strict scope boundaries, and catalog exposed attack surfaces.',
    whyThisMatters:
      'Complete visibility into application architecture is necessary to enforce security boundaries and prevent unauthorized endpoint exploitation.',
    remediationSteps: [
      'Catalog all active API routes and endpoints.',
      'Enforce explicit authentication scopes.',
      'Isolate system administrative execution surfaces.',
      'Scan configuration files for exposed secrets.',
      'Document security boundary mappings.',
    ],
  },

  'threat-model': {
    id: 'threat-model',
    title: 'Threat Model Analysis',
    category: 'Threat Modeling',
    cvss: '9.5',
    severity: 'CRITICAL',
    description:
      'Analyzes identified assets, trust boundaries, attack paths, threat actors, and security risk scenarios across application components.',
    attackScenario:
      'An adversary exploits weak trust boundaries between user input parsing and model execution to inject privileged system commands.',
    businessImpact:
      'Undefined trust boundaries allow untrusted data to manipulate execution logic, causing privilege escalation and data compromise.',
    originalCode: `// BEFORE IMPLEMENTATION:
Unidentified trust boundaries
Unmapped attack paths
Unknown threat actor scenarios
Unrated vulnerability risks`,
    patchedCode: `// AFTER SECURITY MITIGATION:
Trust boundaries defined & validated
Attack paths analyzed & isolated
Threat actors mapped to vectors
Risk scenarios classified by CVSS`,
    expectedChanges:
      'Establish explicit trust boundaries between untrusted inputs and core AI execution models.',
    whyThisMatters:
      'Threat modeling ensures potential attack pathways are evaluated and mitigated before exploitation occurs.',
    remediationSteps: [
      'Define trust boundaries for model input ingestion.',
      'Map potential attack paths across agent tools.',
      'Classify threat scenarios by severity.',
      'Implement boundary enforcement policies.',
      'Validate mitigation coverage across components.',
    ],
  },

  'vector-analysis': {
    id: 'vector-analysis',
    title: 'Threat Vector Analysis',
    category: 'Vector Analysis',
    cvss: '9.1',
    severity: 'CRITICAL',
    description:
      'Analyzes detected attack vectors, CVSS severity ratings, exploitability, affected components, and potential system impact.',
    attackScenario:
      'An attacker leverages prompt injection or tool invocation vectors to bypass application guards and execute destructive commands.',
    businessImpact:
      'Uncontrolled vector propagation can lead to arbitrary code execution, resource destruction, and secret key exfiltration.',
    originalCode: `// BEFORE IMPLEMENTATION:
Unclassified attack vectors
Unknown CVSS severity
Unverified payload exploitability
Unidentified affected components`,
    patchedCode: `// AFTER SECURITY MITIGATION:
Attack vectors classified & rated
CVSS v3.1 severity calculated
Exploitability verified & contained
Affected components isolated & guarded`,
    expectedChanges:
      'Isolate high-severity attack vectors and implement schema validation for dynamic tool execution.',
    whyThisMatters:
      'Vector analysis provides granular CVSS scoring to prioritize critical security patches.',
    remediationSteps: [
      'Evaluate prompt injection attack vectors.',
      'Verify tool execution permission guards.',
      'Calculate CVSS severity ratings for discovered vectors.',
      'Isolate vulnerable application components.',
      'Implement payload sanitization controls.',
    ],
  },

  remediation: {
    id: 'remediation',
    title: 'Security Remediation',
    category: 'Remediation',
    cvss: '8.8',
    severity: 'CRITICAL',
    description:
      'Applies active mitigation strategies to identified vulnerabilities, enforces tool guards, and hardens exposed attack surfaces.',
    attackScenario:
      'Without active remediation, identified vulnerabilities remain accessible to unauthorized network clients.',
    businessImpact:
      'Unpatched vulnerabilities allow persistent security risks and non-compliance with data protection standards.',
    originalCode: `// BEFORE IMPLEMENTATION:
Known vulnerabilities remain exploitable
Missing destructive tool guards
Unprotected sensitive API routes
Unsanitized user prompt inputs`,
    patchedCode: `// AFTER SECURITY MITIGATION:
Mitigation controls applied & active
Destructive tool RBAC guards enforced
Endpoint JWT authentication activated
Input & prompt sanitization enabled`,
    expectedChanges:
      'Deploy active security patches, input sanitization middleware, and role-based access guards.',
    whyThisMatters:
      'Immediate remediation neutralizes threat vectors and restores system security integrity.',
    remediationSteps: [
      'Apply prompt sanitization to user input streams.',
      'Enforce role-based access control on destructive tools.',
      'Activate JWT authentication middleware on API routes.',
      'Implement strict rate limiting on public endpoints.',
      'Verify patch deployment across all services.',
    ],
  },

  'patch-verify': {
    id: 'patch-verify',
    title: 'Patch Verification',
    category: 'Patch Verify',
    cvss: '7.5',
    severity: 'HIGH',
    description:
      'Verifies that applied security patches and mitigations successfully eliminate vulnerabilities without introducing regressions.',
    attackScenario:
      'An attacker attempts regression exploits against applied patches to find bypass mechanisms or incomplete fixes.',
    businessImpact:
      'Incompletely verified security patches provide false assurance while leaving system vulnerabilities open to exploitation.',
    originalCode: `// BEFORE IMPLEMENTATION:
Patch effectiveness unverified
Exploit payloads remain untested
Residual vulnerabilities unknown
Security controls unvalidated`,
    patchedCode: `// AFTER SECURITY MITIGATION:
Security patches verified via red-teaming
Vulnerabilities re-tested & confirmed closed
Residual risk calculated & mitigated
All security controls validated active`,
    expectedChanges:
      'Perform automated red-team exploit suites against security patches to confirm complete vulnerability resolution.',
    whyThisMatters:
      'Verification ensures security patches withstand hostile exploitation attempts and operate correctly.',
    remediationSteps: [
      'Run automated red-team prompt injection test suites.',
      'Verify payload blocking on protected endpoints.',
      'Confirm zero residual privilege escalation paths.',
      'Validate error logging for blocked attacks.',
      'Sign off patch verification results.',
    ],
  },

  report: {
    id: 'report',
    title: 'Security Audit Report',
    category: 'Report',
    cvss: '5.5',
    severity: 'MEDIUM',
    description:
      'Generates the final security audit report containing consolidated findings, mitigation statuses, verification results, and posture.',
    attackScenario:
      'Lack of security audit documentation prevents compliance reporting and leaves management unaware of system risk posture.',
    businessImpact:
      'Incomplete audit reporting hampers compliance compliance certification and executive security governance.',
    originalCode: `// BEFORE IMPLEMENTATION:
Audit findings un-consolidated
Unverified mitigation statuses
Pending security posture score
Un-compiled compliance documentation`,
    patchedCode: `// AFTER SECURITY MITIGATION:
Audit findings consolidated & cataloged
Mitigation statuses verified 100%
Final production readiness score verified
Comprehensive audit report generated`,
    expectedChanges:
      'Compile final vulnerability metrics, remediation statuses, and production security readiness score.',
    whyThisMatters:
      'Audit reports document compliance, verify security readiness, and provide actionable security guidance.',
    remediationSteps: [
      'Consolidate discovered vulnerability metrics.',
      'Document mitigation actions and verification results.',
      'Calculate production security readiness score.',
      'Export audit report for compliance reviews.',
      'Archive audit logs for governance tracking.',
    ],
  },
};

export function getNodeDetails(key) {
  if (!key && key !== 0) return NODE_THREAT_DETAILS['discovery'];

  if (typeof key === 'object') {
    if (key.key && NODE_THREAT_DETAILS[key.key]) return NODE_THREAT_DETAILS[key.key];
    if (key.id && NODE_THREAT_DETAILS[key.id]) return NODE_THREAT_DETAILS[key.id];
    return key;
  }

  const strKey = String(key).toLowerCase().trim();

  if (NODE_THREAT_DETAILS[strKey]) {
    return NODE_THREAT_DETAILS[strKey];
  }

  if (strKey === '1' || strKey === 'discovery') return NODE_THREAT_DETAILS['discovery'];
  if (strKey === '2' || strKey === 'threat-model' || strKey === 'threat_model') return NODE_THREAT_DETAILS['threat-model'];
  if (strKey === '3' || strKey === 'vector-analysis' || strKey === 'vector_analysis') return NODE_THREAT_DETAILS['vector-analysis'];
  if (strKey === '4' || strKey === 'remediation') return NODE_THREAT_DETAILS['remediation'];
  if (strKey === '5' || strKey === 'patch-verify' || strKey === 'patch_verify') return NODE_THREAT_DETAILS['patch-verify'];
  if (strKey === '6' || strKey === 'report') return NODE_THREAT_DETAILS['report'];

  return NODE_THREAT_DETAILS['discovery'];
}
