export const SECURITY_THREATS = {
  'prompt-injection': {
    id: 'prompt-injection',
    alias: 'prompt_injection',
    title: 'Prompt injection vulnerability',
    category: 'Prompt Security',
    cvss: '9.8',
    severity: 'CRITICAL',
    description:
      'User-controlled instructions can manipulate the AI agent into ignoring its intended system behavior and executing unauthorized instructions.',
    attackScenario:
      'An attacker submits specially crafted instructions designed to override system prompts, manipulate agent behavior, expose hidden instructions, or cause the model to perform unintended actions.',
    businessImpact:
      'Successful prompt injection can lead to unauthorized data disclosure, unsafe tool execution, manipulation of agent responses, and compromise of trusted AI workflows.',
    originalCode: `const response = await agent.run(userInput);
return response;`,
    patchedCode: `const sanitizedInput = sanitizePrompt(userInput);

const response = await agent.run({
  systemPolicy,
  input: sanitizedInput,
  enforcePolicy: true
});

return response;`,
    expectedChanges:
      'Add prompt validation, input sanitization, policy enforcement, and instruction-boundary protection before sending user input to the AI agent.',
    whyThisMatters:
      'AI agents must distinguish trusted system instructions from untrusted user input. Without this separation, malicious input can influence privileged agent behavior.',
    remediationSteps: [
      '1. Validate and sanitize user-controlled prompts.',
      '2. Separate system instructions from user content.',
      '3. Enforce system-level policy checks.',
      '4. Prevent user input from overriding trusted instructions.',
      '5. Add prompt-injection security tests.',
    ],
  },
  'no-delete-tool-guard': {
    id: 'no-delete-tool-guard',
    alias: 'delete_no_guard',
    title: 'No delete tool guard',
    category: 'Tool Security',
    cvss: '9.5',
    severity: 'CRITICAL',
    description:
      'Delete-capable tools can potentially be invoked without sufficient authorization or role verification.',
    attackScenario:
      'An attacker or unauthorized user could manipulate the agent into invoking a destructive tool and deleting files, records, or protected resources.',
    businessImpact:
      'Unauthorized destructive operations can cause data loss, service disruption, compliance issues, and potentially irreversible business damage.',
    originalCode: `await tools.deleteResource(resourceId);`,
    patchedCode: `if (!user || !user.permissions.includes("resource:delete")) {
  throw new Error("Delete permission required");
}

await tools.deleteResource(resourceId);`,
    expectedChanges:
      'Add explicit permission validation and role-based authorization before executing destructive tools.',
    whyThisMatters:
      'Destructive tools require stronger authorization than normal read operations. Every delete operation must verify the user\'s permissions before execution.',
    remediationSteps: [
      '1. Add delete-specific permissions.',
      '2. Validate the authenticated user.',
      '3. Enforce RBAC before tool execution.',
      '4. Require confirmation for destructive operations where appropriate.',
      '5. Log destructive tool executions.',
    ],
  },
  'endpoint-authentication': {
    id: 'endpoint-authentication',
    alias: 'no_endpoint_auth',
    title: 'No endpoint authentication',
    category: 'Authentication',
    cvss: '9.1',
    severity: 'CRITICAL',
    description:
      'Sensitive API endpoints can be accessed without verifying an authenticated session.',
    attackScenario:
      'An attacker can directly call protected API endpoints without presenting valid authentication credentials.',
    businessImpact:
      'Unauthenticated access can expose protected resources, modify application data, and bypass authorization controls.',
    originalCode: `app.get("/api/data", async (req, res) => {
  const data = await getData();
  res.json(data);
});`,
    patchedCode: `app.get(
  "/api/data",
  authenticateJWT,
  authorize("read:data"),
  async (req, res) => {
    const data = await getData();
    res.json(data);
  }
);`,
    expectedChanges:
      'Protect sensitive endpoints with authentication middleware and role/permission authorization.',
    whyThisMatters:
      'Authentication verifies the request belongs to a valid user, while authorization ensures that user has permission to access the requested resource.',
    remediationSteps: [
      '1. Add JWT/session authentication middleware.',
      '2. Protect all sensitive endpoints.',
      '3. Add role-based authorization.',
      '4. Validate token expiration.',
      '5. Return proper 401/403 responses.',
    ],
  },
  'secret-token-leakage': {
    id: 'secret-token-leakage',
    alias: 'token_leakage',
    title: 'Token / secret leakage',
    category: 'Credential Security',
    cvss: '8.8',
    severity: 'CRITICAL',
    description:
      'Sensitive API keys, tokens, or credentials may be exposed through source code, logs, client-side bundles, or unsafe configuration.',
    attackScenario:
      'An attacker who obtains exposed credentials can use them to access protected APIs, databases, cloud services, or internal systems.',
    businessImpact:
      'Credential exposure can result in unauthorized system access, data theft, financial loss, service abuse, and application compromise.',
    originalCode: `const API_KEY = "sk_live_xxxxxxxxx";
console.log("API KEY:", API_KEY);`,
    patchedCode: `const API_KEY = process.env.API_KEY;

if (!API_KEY) {
  throw new Error("API_KEY is not configured");
}`,
    expectedChanges:
      'Move secrets to secure environment configuration, remove credentials from source code and logs, and rotate previously exposed secrets.',
    whyThisMatters:
      'Secrets embedded in source code or logs can reach version control systems, browser bundles, monitoring systems, or third parties.',
    remediationSteps: [
      '1. Remove hard-coded credentials.',
      '2. Store secrets in environment variables or a secret manager.',
      '3. Remove sensitive values from logs.',
      '4. Rotate exposed credentials.',
      '5. Scan repository history for leaked secrets.',
    ],
  },
  'rate-limiting': {
    id: 'rate-limiting',
    alias: 'no_rate_limit',
    title: 'No rate limiting',
    category: 'Authentication',
    cvss: '7.5',
    severity: 'HIGH',
    description:
      'Sensitive endpoints do not enforce sufficient request-rate restrictions.',
    attackScenario:
      'An attacker can repeatedly send requests to authentication or API endpoints to perform brute-force attempts, abuse resources, or cause excessive server load.',
    businessImpact:
      'Missing rate limits can enable credential attacks, API abuse, denial-of-service conditions, and unexpected infrastructure costs.',
    originalCode: `app.post("/api/login", loginController);`,
    patchedCode: `const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10
});

app.post(
  "/api/login",
  loginLimiter,
  loginController
);`,
    expectedChanges:
      'Add endpoint-specific rate limiting, especially for authentication and resource-intensive APIs.',
    whyThisMatters:
      'Rate limiting reduces automated abuse and prevents attackers from making unlimited requests against sensitive endpoints.',
    remediationSteps: [
      '1. Add rate limiting middleware.',
      '2. Apply stricter limits to login endpoints.',
      '3. Add IP/user-based throttling where appropriate.',
      '4. Return HTTP 429 when limits are exceeded.',
      '5. Monitor repeated abuse patterns.',
    ],
  },
  'env-git-commit': {
    id: 'env-git-commit',
    alias: 'env_commit_risk',
    title: '.env git commit risk',
    category: 'Credential Security',
    cvss: '7.5',
    severity: 'MEDIUM',
    description:
      '.env is not excluded from Git, creating a risk that sensitive credentials could be accidentally committed.',
    attackScenario:
      'An attacker with access to the repository can extract API keys, database passwords, tokens, and other secrets from a committed .env file.',
    businessImpact:
      'Exposure of environment credentials can provide unauthorized access to databases, APIs, cloud services, and protected systems.',
    originalCode: `__pycache__/
venv/
*.pyc`,
    patchedCode: `.env
*.env
!.env.example

__pycache__/
venv/
*.pyc
output.txt
agent_reply.txt`,
    expectedChanges:
      'Add .env and *.env to .gitignore while keeping .env.example available for safe configuration documentation.',
    whyThisMatters:
      'Environment files frequently contain credentials and tokens. Accidentally committing them can expose secrets permanently through repository history.',
    remediationSteps: [
      '1. Add .env and *.env to .gitignore.',
      '2. Remove already-tracked .env files using git rm --cached.',
      '3. Search Git history for previously exposed secrets.',
      '4. Rotate exposed credentials immediately.',
      '5. Use .env.example for non-secret configuration documentation.',
    ],
  },
};

import { VERTEX_DATA_HUB_THREATS, VERTEX_DATA_HUB_FINDINGS } from './vertexDataHubThreats';
import { SENTINEL_CORE_THREATS, SENTINEL_CORE_FINDINGS } from './sentinelCoreThreats';
import { ATLAS_SECURE_THREATS, ATLAS_SECURE_FINDINGS } from './atlasSecureThreats';
import { QUANTUM_OPS_THREATS, QUANTUM_OPS_FINDINGS } from './quantumOpsThreats';
import { AEGIS_ONE_THREATS, AEGIS_ONE_FINDINGS } from './aegisOneThreats';

export {
  VERTEX_DATA_HUB_THREATS,
  VERTEX_DATA_HUB_FINDINGS,
  SENTINEL_CORE_THREATS,
  SENTINEL_CORE_FINDINGS,
  ATLAS_SECURE_THREATS,
  ATLAS_SECURE_FINDINGS,
  QUANTUM_OPS_THREATS,
  QUANTUM_OPS_FINDINGS,
  AEGIS_ONE_THREATS,
  AEGIS_ONE_FINDINGS,
};

export const PROJECT_AUDIT_DATA = {
  'AegisOne Platform': {
    findings: AEGIS_ONE_FINDINGS,
  },
  'aegisone': {
    findings: AEGIS_ONE_FINDINGS,
  },
  'Vertex Data Hub': {
    findings: VERTEX_DATA_HUB_FINDINGS,
  },
  'vertex_hub': {
    findings: VERTEX_DATA_HUB_FINDINGS,
  },
  'SentinelCore': {
    findings: SENTINEL_CORE_FINDINGS,
  },
  'sentinel_core': {
    findings: SENTINEL_CORE_FINDINGS,
  },
  'Atlas Secure Systems': {
    findings: ATLAS_SECURE_FINDINGS,
  },
  'atlas_systems': {
    findings: ATLAS_SECURE_FINDINGS,
  },
  'QuantumOps': {
    findings: QUANTUM_OPS_FINDINGS,
  },
  'quantum_ops': {
    findings: QUANTUM_OPS_FINDINGS,
  },
};

// Threat ID Aliases and helper functions
export const THREAT_ID_ALIASES = {
  'prompt_injection': ['prompt_injection', 'prompt-injection', 'vertex_prompt_injection', 'vertex-prompt-injection', 'sentinel_unauthorized_api_access', 'sentinel-unauthorized-api-access', 'atlas_insecure_deserialization', 'atlas-insecure-deserialization', 'quantum_insecure_data_serialization', 'quantum-insecure-data-serialization', 'aegis_insecure_auth_flow', 'aegis-insecure-authentication-flow'],
  'prompt-injection': ['prompt_injection', 'prompt-injection', 'vertex_prompt_injection', 'vertex-prompt-injection', 'sentinel_unauthorized_api_access', 'sentinel-unauthorized-api-access', 'atlas_insecure_deserialization', 'atlas-insecure-deserialization', 'quantum_insecure_data_serialization', 'quantum-insecure-data-serialization', 'aegis_insecure_auth_flow', 'aegis-insecure-authentication-flow'],
  'vertex_prompt_injection': ['vertex_prompt_injection', 'vertex-prompt-injection', 'prompt_injection', 'prompt-injection'],
  'vertex-prompt-injection': ['vertex_prompt_injection', 'vertex-prompt-injection', 'prompt_injection', 'prompt-injection'],
  'sentinel_unauthorized_api_access': ['sentinel_unauthorized_api_access', 'sentinel-unauthorized-api-access', 'prompt_injection', 'prompt-injection'],
  'sentinel-unauthorized-api-access': ['sentinel_unauthorized_api_access', 'sentinel-unauthorized-api-access', 'prompt_injection', 'prompt-injection'],
  'atlas_insecure_deserialization': ['atlas_insecure_deserialization', 'atlas-insecure-deserialization', 'prompt_injection', 'prompt-injection'],
  'atlas-insecure-deserialization': ['atlas_insecure_deserialization', 'atlas-insecure-deserialization', 'prompt_injection', 'prompt-injection'],
  'quantum_insecure_data_serialization': ['quantum_insecure_data_serialization', 'quantum-insecure-data-serialization', 'prompt_injection', 'prompt-injection'],
  'quantum-insecure-data-serialization': ['quantum_insecure_data_serialization', 'quantum-insecure-data-serialization', 'prompt_injection', 'prompt-injection'],
  'aegis_insecure_auth_flow': ['aegis_insecure_auth_flow', 'aegis-insecure-authentication-flow', 'no_endpoint_auth', 'endpoint-authentication', 'prompt_injection', 'prompt-injection'],
  'aegis-insecure-authentication-flow': ['aegis_insecure_auth_flow', 'aegis-insecure-authentication-flow', 'no_endpoint_auth', 'endpoint-authentication', 'prompt_injection', 'prompt-injection'],

  'delete_no_guard': ['delete_no_guard', 'no-delete-tool-guard', 'vertex_delete_guard', 'vertex-delete-guard', 'sentinel_privilege_escalation', 'sentinel-privilege-escalation', 'atlas_improper_token_verification', 'atlas-improper-token-verification', 'quantum_excessive_privilege_assignment', 'quantum-excessive-privilege-assignment', 'aegis_broken_access_control', 'aegis-broken-access-control'],
  'no-delete-tool-guard': ['delete_no_guard', 'no-delete-tool-guard', 'vertex_delete_guard', 'vertex-delete-guard', 'sentinel_privilege_escalation', 'sentinel-privilege-escalation', 'atlas_improper_token_verification', 'atlas-improper-token-verification', 'quantum_excessive_privilege_assignment', 'quantum-excessive-privilege-assignment', 'aegis_broken_access_control', 'aegis-broken-access-control'],
  'vertex_delete_guard': ['vertex_delete_guard', 'vertex-delete-guard', 'delete_no_guard', 'no-delete-tool-guard'],
  'vertex-delete-guard': ['vertex_delete_guard', 'vertex-delete-guard', 'delete_no_guard', 'no-delete-tool-guard'],
  'sentinel_privilege_escalation': ['sentinel_privilege_escalation', 'sentinel-privilege-escalation', 'delete_no_guard', 'no-delete-tool-guard'],
  'sentinel-privilege-escalation': ['sentinel_privilege_escalation', 'sentinel-privilege-escalation', 'delete_no_guard', 'no-delete-tool-guard'],
  'atlas_improper_token_verification': ['atlas_improper_token_verification', 'atlas-improper-token-verification', 'delete_no_guard', 'no-delete-tool-guard'],
  'atlas-improper-token-verification': ['atlas_improper_token_verification', 'atlas-improper-token-verification', 'delete_no_guard', 'no-delete-tool-guard'],
  'quantum_excessive_privilege_assignment': ['quantum_excessive_privilege_assignment', 'quantum-excessive-privilege-assignment', 'delete_no_guard', 'no-delete-tool-guard'],
  'quantum-excessive-privilege-assignment': ['quantum_excessive_privilege_assignment', 'quantum-excessive-privilege-assignment', 'delete_no_guard', 'no-delete-tool-guard'],
  'aegis_broken_access_control': ['aegis_broken_access_control', 'aegis-broken-access-control', 'delete_no_guard', 'no-delete-tool-guard'],
  'aegis-broken-access-control': ['aegis_broken_access_control', 'aegis-broken-access-control', 'delete_no_guard', 'no-delete-tool-guard'],

  'no_endpoint_auth': ['no_endpoint_auth', 'endpoint-authentication', 'vertex_missing_endpoint_auth', 'vertex-missing-endpoint-auth', 'sentinel_insecure_session_handling', 'sentinel-insecure-session-handling', 'atlas_cryptographic_key_flaw', 'atlas-cryptographic-key-flaw', 'quantum_missing_api_authorization', 'quantum-missing-api-authorization', 'aegis_insecure_auth_flow', 'aegis-insecure-authentication-flow'],
  'endpoint-authentication': ['no_endpoint_auth', 'endpoint-authentication', 'vertex_missing_endpoint_auth', 'vertex-missing-endpoint-auth', 'sentinel_insecure_session_handling', 'sentinel-insecure-session-handling', 'atlas_cryptographic_key_flaw', 'atlas-cryptographic-key-flaw', 'quantum_missing_api_authorization', 'quantum-missing-api-authorization', 'aegis_insecure_auth_flow', 'aegis-insecure-authentication-flow'],
  'vertex_missing_endpoint_auth': ['vertex_missing_endpoint_auth', 'vertex-missing-endpoint-auth', 'no_endpoint_auth', 'endpoint-authentication'],
  'vertex-missing-endpoint-auth': ['vertex_missing_endpoint_auth', 'vertex-missing-endpoint-auth', 'no_endpoint_auth', 'endpoint-authentication'],
  'sentinel_insecure_session_handling': ['sentinel_insecure_session_handling', 'sentinel-insecure-session-handling', 'no_endpoint_auth', 'endpoint-authentication'],
  'sentinel-insecure-session-handling': ['sentinel_insecure_session_handling', 'sentinel-insecure-session-handling', 'no_endpoint_auth', 'endpoint-authentication'],
  'atlas_cryptographic_key_flaw': ['atlas_cryptographic_key_flaw', 'atlas-cryptographic-key-flaw', 'no_endpoint_auth', 'endpoint-authentication'],
  'atlas-cryptographic-key-flaw': ['atlas_cryptographic_key_flaw', 'atlas-cryptographic-key-flaw', 'no_endpoint_auth', 'endpoint-authentication'],
  'quantum_missing_api_authorization': ['quantum_missing_api_authorization', 'quantum-missing-api-authorization', 'no_endpoint_auth', 'endpoint-authentication'],
  'quantum-missing-api-authorization': ['quantum_missing_api_authorization', 'quantum-missing-api-authorization', 'no_endpoint_auth', 'endpoint-authentication'],

  'token_leakage': ['token_leakage', 'secret-token-leakage', 'vertex_token_leakage', 'vertex-token-leakage', 'sentinel_sensitive_data_exposure', 'sentinel-sensitive-data-exposure', 'atlas_unrestricted_microsegmentation', 'atlas-unrestricted-microsegmentation', 'quantum_api_key_exposure', 'quantum-api-key-exposure', 'aegis_sensitive_data_exposure', 'aegis-sensitive-customer-data-exposure'],
  'secret-token-leakage': ['token_leakage', 'secret-token-leakage', 'vertex_token_leakage', 'vertex-token-leakage', 'sentinel_sensitive_data_exposure', 'sentinel-sensitive-data-exposure', 'atlas_unrestricted_microsegmentation', 'atlas-unrestricted-microsegmentation', 'quantum_api_key_exposure', 'quantum-api-key-exposure', 'aegis_sensitive_data_exposure', 'aegis-sensitive-customer-data-exposure'],
  'vertex_token_leakage': ['vertex_token_leakage', 'vertex-token-leakage', 'token_leakage', 'secret-token-leakage'],
  'vertex-token-leakage': ['vertex_token_leakage', 'vertex-token-leakage', 'token_leakage', 'secret-token-leakage'],
  'sentinel_sensitive_data_exposure': ['sentinel_sensitive_data_exposure', 'sentinel-sensitive-data-exposure', 'token_leakage', 'secret-token-leakage'],
  'sentinel-sensitive-data-exposure': ['sentinel_sensitive_data_exposure', 'sentinel-sensitive-data-exposure', 'token_leakage', 'secret-token-leakage'],
  'atlas_unrestricted_microsegmentation': ['atlas_unrestricted_microsegmentation', 'atlas-unrestricted-microsegmentation', 'token_leakage', 'secret-token-leakage'],
  'atlas-unrestricted-microsegmentation': ['atlas_unrestricted_microsegmentation', 'atlas-unrestricted-microsegmentation', 'token_leakage', 'secret-token-leakage'],
  'quantum_api_key_exposure': ['quantum_api_key_exposure', 'quantum-api-key-exposure', 'token_leakage', 'secret-token-leakage'],
  'quantum-api-key-exposure': ['quantum_api_key_exposure', 'quantum-api-key-exposure', 'token_leakage', 'secret-token-leakage'],
  'aegis_sensitive_data_exposure': ['aegis_sensitive_data_exposure', 'aegis-sensitive-customer-data-exposure', 'token_leakage', 'secret-token-leakage'],
  'aegis-sensitive-customer-data-exposure': ['aegis_sensitive_data_exposure', 'aegis-sensitive-customer-data-exposure', 'token_leakage', 'secret-token-leakage'],

  'no_rate_limit': ['no_rate_limit', 'rate-limiting', 'vertex_no_rate_limiting', 'vertex-no-rate-limiting', 'sentinel_missing_rate_limiting', 'sentinel-missing-rate-limiting', 'atlas_audit_log_tampering', 'atlas-audit-log-tampering', 'quantum_insufficient_audit_logging', 'quantum-insufficient-audit-logging', 'aegis_missing_api_rate_limiting', 'aegis-missing-api-rate-limiting', 'aegis_insufficient_security_logging', 'aegis-insufficient-security-logging'],
  'rate-limiting': ['no_rate_limit', 'rate-limiting', 'vertex_no_rate_limiting', 'vertex-no-rate-limiting', 'sentinel_missing_rate_limiting', 'sentinel-missing-rate-limiting', 'atlas_audit_log_tampering', 'atlas-audit-log-tampering', 'quantum_insufficient_audit_logging', 'quantum-insufficient-audit-logging', 'aegis_missing_api_rate_limiting', 'aegis-missing-api-rate-limiting', 'aegis_insufficient_security_logging', 'aegis-insufficient-security-logging'],
  'vertex_no_rate_limiting': ['vertex_no_rate_limiting', 'vertex-no-rate-limiting', 'no_rate_limit', 'rate-limiting'],
  'vertex-no-rate-limiting': ['vertex_no_rate_limiting', 'vertex-no-rate-limiting', 'no_rate_limit', 'rate-limiting'],
  'sentinel_missing_rate_limiting': ['sentinel_missing_rate_limiting', 'sentinel-missing-rate-limiting', 'no_rate_limit', 'rate-limiting'],
  'sentinel-missing-rate-limiting': ['sentinel_missing_rate_limiting', 'sentinel-missing-rate-limiting', 'no_rate_limit', 'rate-limiting'],
  'atlas_audit_log_tampering': ['atlas_audit_log_tampering', 'atlas-audit-log-tampering', 'no_rate_limit', 'rate-limiting'],
  'atlas-audit-log-tampering': ['atlas_audit_log_tampering', 'atlas-audit-log-tampering', 'no_rate_limit', 'rate-limiting'],
  'quantum_insufficient_audit_logging': ['quantum_insufficient_audit_logging', 'quantum-insufficient-audit-logging', 'no_rate_limit', 'rate-limiting'],
  'quantum-insufficient-audit-logging': ['quantum_insufficient_audit_logging', 'quantum-insufficient-audit-logging', 'no_rate_limit', 'rate-limiting'],
  'aegis_missing_api_rate_limiting': ['aegis_missing_api_rate_limiting', 'aegis-missing-api-rate-limiting', 'no_rate_limit', 'rate-limiting'],
  'aegis-missing-api-rate-limiting': ['aegis_missing_api_rate_limiting', 'aegis-missing-api-rate-limiting', 'no_rate_limit', 'rate-limiting'],
  'aegis_insufficient_security_logging': ['aegis_insufficient_security_logging', 'aegis-insufficient-security-logging', 'no_rate_limit', 'rate-limiting'],
  'aegis-insufficient-security-logging': ['aegis_insufficient_security_logging', 'aegis-insufficient-security-logging', 'no_rate_limit', 'rate-limiting'],

  'env_commit_risk': ['env_commit_risk', 'env-git-commit', 'vertex_env_secret_exposure', 'vertex-env-secret-exposure', 'sentinel_weak_input_validation', 'sentinel-weak-input-validation', 'atlas_unbounded_session_allocation', 'atlas-unbounded-session-allocation', 'quantum_missing_request_validation', 'quantum-missing-request-validation', 'aegis_unsafe_input_handling', 'aegis-unsafe-input-handling'],
  'env-git-commit': ['env_commit_risk', 'env-git-commit', 'vertex_env_secret_exposure', 'vertex-env-secret-exposure', 'sentinel_weak_input_validation', 'sentinel-weak-input-validation', 'atlas_unbounded_session_allocation', 'atlas-unbounded-session-allocation', 'quantum_missing_request_validation', 'quantum-missing-request-validation', 'aegis_unsafe_input_handling', 'aegis-unsafe-input-handling'],
  'vertex_env_secret_exposure': ['vertex_env_secret_exposure', 'vertex-env-secret-exposure', 'env_commit_risk', 'env-git-commit'],
  'vertex-env-secret-exposure': ['vertex_env_secret_exposure', 'vertex-env-secret-exposure', 'env_commit_risk', 'env-git-commit'],
  'sentinel_weak_input_validation': ['sentinel_weak_input_validation', 'sentinel-weak-input-validation', 'env_commit_risk', 'env-git-commit'],
  'sentinel-weak-input-validation': ['sentinel_weak_input_validation', 'sentinel-weak-input-validation', 'env_commit_risk', 'env-git-commit'],
  'atlas_unbounded_session_allocation': ['atlas_unbounded_session_allocation', 'atlas-unbounded-session-allocation', 'env_commit_risk', 'env-git-commit'],
  'atlas-unbounded-session-allocation': ['atlas_unbounded_session_allocation', 'atlas-unbounded-session-allocation', 'env_commit_risk', 'env-git-commit'],
  'quantum_missing_request_validation': ['quantum_missing_request_validation', 'quantum-missing-request-validation', 'env_commit_risk', 'env-git-commit'],
  'quantum-missing-request-validation': ['quantum_missing_request_validation', 'quantum-missing-request-validation', 'env_commit_risk', 'env-git-commit'],
  'aegis_unsafe_input_handling': ['aegis_unsafe_input_handling', 'aegis-unsafe-input-handling', 'env_commit_risk', 'env-git-commit'],
  'aegis-unsafe-input-handling': ['aegis_unsafe_input_handling', 'aegis-unsafe-input-handling', 'env_commit_risk', 'env-git-commit'],
};

export function matchesThreatId(idA, idB) {
  if (!idA || !idB) return false;
  if (idA === idB) return true;
  const aliasesA = THREAT_ID_ALIASES[idA] || [idA];
  if (aliasesA.includes(idB)) return true;
  const aliasesB = THREAT_ID_ALIASES[idB] || [idB];
  return aliasesB.includes(idA);
}

export function getBackendThreatId(threatId) {
  if (!threatId) return threatId;
  const mapping = {
    'prompt-injection': 'prompt_injection',
    'prompt_injection': 'prompt_injection',
    'vertex_prompt_injection': 'prompt_injection',
    'vertex-prompt-injection': 'prompt_injection',
    'sentinel_unauthorized_api_access': 'prompt_injection',
    'sentinel-unauthorized-api-access': 'prompt_injection',
    'atlas_insecure_deserialization': 'prompt_injection',
    'atlas-insecure-deserialization': 'prompt_injection',
    'quantum_insecure_data_serialization': 'prompt_injection',
    'quantum-insecure-data-serialization': 'prompt_injection',
    'aegis_insecure_auth_flow': 'no_endpoint_auth',
    'aegis-insecure-authentication-flow': 'no_endpoint_auth',

    'no-delete-tool-guard': 'delete_no_guard',
    'delete_no_guard': 'delete_no_guard',
    'vertex_delete_guard': 'delete_no_guard',
    'vertex-delete-guard': 'delete_no_guard',
    'sentinel_privilege_escalation': 'delete_no_guard',
    'sentinel-privilege-escalation': 'delete_no_guard',
    'atlas_improper_token_verification': 'delete_no_guard',
    'atlas-improper-token-verification': 'delete_no_guard',
    'quantum_excessive_privilege_assignment': 'delete_no_guard',
    'quantum-excessive-privilege-assignment': 'delete_no_guard',
    'aegis_broken_access_control': 'delete_no_guard',
    'aegis-broken-access-control': 'delete_no_guard',

    'endpoint-authentication': 'no_endpoint_auth',
    'no_endpoint_auth': 'no_endpoint_auth',
    'vertex_missing_endpoint_auth': 'no_endpoint_auth',
    'vertex-missing-endpoint-auth': 'no_endpoint_auth',
    'sentinel_insecure_session_handling': 'no_endpoint_auth',
    'sentinel-insecure-session-handling': 'no_endpoint_auth',
    'atlas_cryptographic_key_flaw': 'no_endpoint_auth',
    'atlas-cryptographic-key-flaw': 'no_endpoint_auth',
    'quantum_missing_api_authorization': 'no_endpoint_auth',
    'quantum-missing-api-authorization': 'no_endpoint_auth',

    'secret-token-leakage': 'token_leakage',
    'token_leakage': 'token_leakage',
    'vertex_token_leakage': 'token_leakage',
    'vertex-token-leakage': 'token_leakage',
    'sentinel_sensitive_data_exposure': 'token_leakage',
    'sentinel-sensitive-data-exposure': 'token_leakage',
    'atlas_unrestricted_microsegmentation': 'token_leakage',
    'atlas-unrestricted-microsegmentation': 'token_leakage',
    'quantum_api_key_exposure': 'token_leakage',
    'quantum-api-key-exposure': 'token_leakage',
    'aegis_sensitive_data_exposure': 'token_leakage',
    'aegis-sensitive-customer-data-exposure': 'token_leakage',

    'rate-limiting': 'no_rate_limit',
    'no_rate_limit': 'no_rate_limit',
    'vertex_no_rate_limiting': 'no_rate_limit',
    'vertex-no-rate-limiting': 'no_rate_limit',
    'sentinel_missing_rate_limiting': 'no_rate_limit',
    'sentinel-missing-rate-limiting': 'no_rate_limit',
    'atlas_audit_log_tampering': 'no_rate_limit',
    'atlas-audit-log-tampering': 'no_rate_limit',
    'quantum_insufficient_audit_logging': 'no_rate_limit',
    'quantum-insufficient-audit-logging': 'no_rate_limit',
    'aegis_missing_api_rate_limiting': 'no_rate_limit',
    'aegis-missing-api-rate-limiting': 'no_rate_limit',
    'aegis_insufficient_security_logging': 'no_rate_limit',
    'aegis-insufficient-security-logging': 'no_rate_limit',

    'env-git-commit': 'env_commit_risk',
    'env_commit_risk': 'env_commit_risk',
    'vertex_env_secret_exposure': 'env_commit_risk',
    'vertex-env-secret-exposure': 'env_commit_risk',
    'sentinel_weak_input_validation': 'env_commit_risk',
    'sentinel-weak-input-validation': 'env_commit_risk',
    'atlas_unbounded_session_allocation': 'env_commit_risk',
    'atlas-unbounded-session-allocation': 'env_commit_risk',
    'quantum_missing_request_validation': 'env_commit_risk',
    'quantum-missing-request-validation': 'env_commit_risk',
    'aegis_unsafe_input_handling': 'env_commit_risk',
    'aegis-unsafe-input-handling': 'env_commit_risk',
  };
  return mapping[threatId] || threatId;
}

// Map threat ID or title or domain to detailed threat record
export function normalizeThreat(threat) {
  if (!threat) return null;

  const key = threat.id || '';
  const title = (threat.title || '').toLowerCase();
  const isAegis = threat.project === 'AegisOne Platform' || key.startsWith('aegis');
  const isQuantum = threat.project === 'QuantumOps' || key.startsWith('quantum');
  const isAtlas = threat.project === 'Atlas Secure Systems' || key.startsWith('atlas');
  const isSentinel = threat.project === 'SentinelCore' || key.startsWith('sentinel');
  const isVertex = threat.project === 'Vertex Data Hub' || key.startsWith('vertex');

  // 1. Check AegisOne Platform dedicated dataset
  if (isAegis || AEGIS_ONE_THREATS[key]) {
    let aegisDef = AEGIS_ONE_THREATS[key];
    if (!aegisDef) {
      aegisDef = Object.values(AEGIS_ONE_THREATS).find(
        (t) => t.alias === key || t.id === key || (t.alias && matchesThreatId(t.alias, key))
      );
    }
    if (!aegisDef) {
      if (title.includes('insecure authentication') || title.includes('auth flow') || title.includes('sso')) aegisDef = AEGIS_ONE_THREATS['aegis-insecure-authentication-flow'];
      else if (title.includes('broken access') || title.includes('access control') || title.includes('idor')) aegisDef = AEGIS_ONE_THREATS['aegis-broken-access-control'];
      else if (title.includes('sensitive') || title.includes('customer data') || title.includes('pii')) aegisDef = AEGIS_ONE_THREATS['aegis-sensitive-customer-data-exposure'];
      else if (title.includes('rate limit') || title.includes('throttling') || title.includes('dos')) aegisDef = AEGIS_ONE_THREATS['aegis-missing-api-rate-limiting'];
      else if (title.includes('input') || title.includes('regex') || title.includes('redos')) aegisDef = AEGIS_ONE_THREATS['aegis-unsafe-input-handling'];
      else if (title.includes('logging') || title.includes('audit') || title.includes('telemetry')) aegisDef = AEGIS_ONE_THREATS['aegis-insufficient-security-logging'];
    }

    if (aegisDef) {
      return {
        ...aegisDef,
        ...threat,
        id: threat.id || aegisDef.id,
        status: threat.status || 'unresolved',
      };
    }
  }

  // 2. Check QuantumOps dedicated dataset
  if (isQuantum || QUANTUM_OPS_THREATS[key]) {
    let quantumDef = QUANTUM_OPS_THREATS[key];
    if (!quantumDef) {
      quantumDef = Object.values(QUANTUM_OPS_THREATS).find(
        (t) => t.alias === key || t.id === key || (t.alias && matchesThreatId(t.alias, key))
      );
    }
    if (!quantumDef) {
      if (title.includes('api key') || title.includes('exposure') || title.includes('secret')) quantumDef = QUANTUM_OPS_THREATS['quantum-api-key-exposure'];
      else if (title.includes('missing api') || title.includes('authorization') || title.includes('auth')) quantumDef = QUANTUM_OPS_THREATS['quantum-missing-api-authorization'];
      else if (title.includes('privilege') || title.includes('excessive')) quantumDef = QUANTUM_OPS_THREATS['quantum-excessive-privilege-assignment'];
      else if (title.includes('serialization') || title.includes('pickle') || title.includes('data')) quantumDef = QUANTUM_OPS_THREATS['quantum-insecure-data-serialization'];
      else if (title.includes('validation') || title.includes('request')) quantumDef = QUANTUM_OPS_THREATS['quantum-missing-request-validation'];
      else if (title.includes('audit') || title.includes('log') || title.includes('insufficient')) quantumDef = QUANTUM_OPS_THREATS['quantum-insufficient-audit-logging'];
    }

    if (quantumDef) {
      return {
        ...quantumDef,
        ...threat,
        id: threat.id || quantumDef.id,
        status: threat.status || 'unresolved',
      };
    }
  }

  // 3. Check Atlas Secure Systems dedicated dataset
  if (isAtlas || ATLAS_SECURE_THREATS[key]) {
    let atlasDef = ATLAS_SECURE_THREATS[key];
    if (!atlasDef) {
      atlasDef = Object.values(ATLAS_SECURE_THREATS).find(
        (t) => t.alias === key || t.id === key || (t.alias && matchesThreatId(t.alias, key))
      );
    }
    if (!atlasDef) {
      if (title.includes('deserialization') || title.includes('state sync')) atlasDef = ATLAS_SECURE_THREATS['atlas-insecure-deserialization'];
      else if (title.includes('token') || title.includes('zero-trust')) atlasDef = ATLAS_SECURE_THREATS['atlas-improper-token-verification'];
      else if (title.includes('key') || title.includes('crypto') || title.includes('permutation')) atlasDef = ATLAS_SECURE_THREATS['atlas-cryptographic-key-flaw'];
      else if (title.includes('microsegmentation') || title.includes('segmentation')) atlasDef = ATLAS_SECURE_THREATS['atlas-unrestricted-microsegmentation'];
      else if (title.includes('audit') || title.includes('tampering') || title.includes('log')) atlasDef = ATLAS_SECURE_THREATS['atlas-audit-log-tampering'];
      else if (title.includes('session') || title.includes('allocation') || title.includes('unbounded')) atlasDef = ATLAS_SECURE_THREATS['atlas-unbounded-session-allocation'];
    }

    if (atlasDef) {
      return {
        ...atlasDef,
        ...threat,
        id: threat.id || atlasDef.id,
        status: threat.status || 'unresolved',
      };
    }
  }

  // 3. Check SentinelCore dedicated dataset
  if (isSentinel || SENTINEL_CORE_THREATS[key]) {
    let sentinelDef = SENTINEL_CORE_THREATS[key];
    if (!sentinelDef) {
      sentinelDef = Object.values(SENTINEL_CORE_THREATS).find(
        (t) => t.alias === key || t.id === key || (t.alias && matchesThreatId(t.alias, key))
      );
    }
    if (!sentinelDef) {
      if (title.includes('unauthorized') || title.includes('api access')) sentinelDef = SENTINEL_CORE_THREATS['sentinel-unauthorized-api-access'];
      else if (title.includes('privilege') || title.includes('escalation')) sentinelDef = SENTINEL_CORE_THREATS['sentinel-privilege-escalation'];
      else if (title.includes('session')) sentinelDef = SENTINEL_CORE_THREATS['sentinel-insecure-session-handling'];
      else if (title.includes('sensitive') || title.includes('exposure')) sentinelDef = SENTINEL_CORE_THREATS['sentinel-sensitive-data-exposure'];
      else if (title.includes('rate')) sentinelDef = SENTINEL_CORE_THREATS['sentinel-missing-rate-limiting'];
      else if (title.includes('validation') || title.includes('input')) sentinelDef = SENTINEL_CORE_THREATS['sentinel-weak-input-validation'];
    }

    if (sentinelDef) {
      return {
        ...sentinelDef,
        ...threat,
        id: threat.id || sentinelDef.id,
        status: threat.status || 'unresolved',
      };
    }
  }

  // 4. Check Vertex Data Hub dedicated dataset
  if (isVertex || VERTEX_DATA_HUB_THREATS[key]) {
    let vertexDef = VERTEX_DATA_HUB_THREATS[key];
    if (!vertexDef) {
      vertexDef = Object.values(VERTEX_DATA_HUB_THREATS).find(
        (t) => t.alias === key || t.id === key || (t.alias && matchesThreatId(t.alias, key))
      );
    }
    if (!vertexDef) {
      if (title.includes('prompt')) vertexDef = VERTEX_DATA_HUB_THREATS['vertex-prompt-injection'];
      else if (title.includes('endpoint') || title.includes('auth')) vertexDef = VERTEX_DATA_HUB_THREATS['vertex-missing-endpoint-auth'];
      else if (title.includes('rate')) vertexDef = VERTEX_DATA_HUB_THREATS['vertex-no-rate-limiting'];
      else if (title.includes('token') || title.includes('leak')) vertexDef = VERTEX_DATA_HUB_THREATS['vertex-token-leakage'];
      else if (title.includes('delete') || title.includes('guard')) vertexDef = VERTEX_DATA_HUB_THREATS['vertex-delete-guard'];
      else if (title.includes('env') || title.includes('secret')) vertexDef = VERTEX_DATA_HUB_THREATS['vertex-env-secret-exposure'];
    }

    if (vertexDef) {
      return {
        ...vertexDef,
        ...threat,
        id: threat.id || vertexDef.id,
        status: threat.status || 'unresolved',
      };
    }
  }

  // 5. If the threat object already has complete custom details, preserve them
  if (threat.attackScenario && threat.businessImpact && (threat.originalCode || threat.diff_before)) {
    return {
      id: threat.id || 'threat-finding',
      title: threat.title || 'Security Threat Finding',
      category: threat.category || threat.domain || 'Security Analysis',
      cvss: threat.cvss ? String(threat.cvss) : '7.0',
      severity: (threat.severity || 'HIGH').toUpperCase(),
      status: threat.status || 'unresolved',
      description: threat.description || 'Details not available for this finding.',
      attackScenario: threat.attackScenario || 'Details not available for this finding.',
      businessImpact: threat.businessImpact || 'Details not available for this finding.',
      originalCode: threat.originalCode || threat.diff_before || '// Code snapshot not available',
      patchedCode: threat.patchedCode || threat.diff_after || '// Security patch snapshot not available',
      expectedChanges: threat.expectedChanges || threat.diff_reason || 'Enforce validation and safe handling.',
      whyThisMatters: threat.whyThisMatters || 'Security controls prevent unauthorized access.',
      remediationSteps: threat.remediationSteps || ['1. Review code.', '2. Apply patch.', '3. Verify security.'],
    };
  }

  // 3. Check DB Agent default SECURITY_THREATS dataset
  let definition = SECURITY_THREATS[key];

  if (!definition) {
    // Find by alias
    definition = Object.values(SECURITY_THREATS).find(
      (t) => t.alias === key || t.id === key || (t.alias && matchesThreatId(t.alias, key))
    );
  }

  if (!definition) {
    // Find by title matching
    if (title.includes('prompt')) {
      definition = SECURITY_THREATS['prompt-injection'];
    } else if (title.includes('delete') || title.includes('guard')) {
      definition = SECURITY_THREATS['no-delete-tool-guard'];
    } else if (title.includes('auth') || title.includes('endpoint')) {
      definition = SECURITY_THREATS['endpoint-authentication'];
    } else if (title.includes('token') || title.includes('leak')) {
      definition = SECURITY_THREATS['secret-token-leakage'];
    } else if (title.includes('rate')) {
      definition = SECURITY_THREATS['rate-limiting'];
    } else if (title.includes('.env') || title.includes('git')) {
      definition = SECURITY_THREATS['env-git-commit'];
    }
  }

  if (definition) {
    return {
      ...definition,
      id: threat.id || definition.id,
      status: threat.status || 'unresolved',
    };
  }

  return {
    id: threat.id || 'unknown-threat',
    title: threat.title || 'Security Threat Finding',
    category: threat.category || threat.domain || 'Security Analysis',
    cvss: threat.cvss ? String(threat.cvss) : '7.0',
    severity: (threat.severity || 'HIGH').toUpperCase(),
    status: threat.status || 'unresolved',
    description: threat.description || 'Details not available for this finding.',
    attackScenario: threat.attackScenario || 'Details not available for this finding.',
    businessImpact: threat.businessImpact || 'Details not available for this finding.',
    originalCode: threat.diff_before || threat.originalCode || '// Code snapshot not available',
    patchedCode: threat.diff_after || threat.patchedCode || '// Security patch snapshot not available',
    expectedChanges: threat.expectedChanges || 'Enforce validation, policy bounds, and safe handling.',
    whyThisMatters: threat.whyThisMatters || 'Security controls prevent unauthorized access and exploit pathways.',
    remediationSteps: threat.remediationSteps || ['1. Review code.', '2. Apply patch.', '3. Verify security.'],
  };
}

