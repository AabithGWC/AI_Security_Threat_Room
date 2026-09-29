/**
 * SentinelCore Dedicated Mock Security Threat Dataset
 * 
 * Project-specific security audit findings for SentinelCore
 * enterprise security orchestration and telemetry platform.
 */

export const SENTINEL_CORE_THREATS = {
  'sentinel-unauthorized-api-access': {
    id: 'sentinel-unauthorized-api-access',
    alias: 'sentinel_unauthorized_api_access',
    stageId: 1,
    project: 'SentinelCore',
    title: 'Unauthorized API Access',
    category: 'API Security',
    domain: 'API Security',
    cvss: '9.5',
    cve: 'CVE-2026-8910',
    severity: 'CRITICAL',
    status: 'unresolved',
    description:
      'SentinelCore telemetry dispatch and event ingestion endpoints allow anonymous clients to dispatch arbitrary cluster telemetry batches without cryptographic API key signature verification or tenant validation.',
    attackScenario:
      'An unauthorized network actor crafts bulk synthetic telemetry events and pushes malicious stream payloads directly to /api/v2/telemetry/ingest, injecting fraudulent security telemetry and bypassing ingress gateways.',
    businessImpact:
      'Poisoning of security monitoring dashboards, loss of telemetry integrity, unmetered resource consumption, and injection of misleading forensic data.',
    originalCode: `@app.post("/api/v2/telemetry/ingest")
async def ingest_telemetry_batch(batch: TelemetryBatch):
    return await event_pipeline.process_events(batch.events)`,
    patchedCode: `from sentinel_auth import verify_api_signature, validate_tenant_claims

@app.post("/api/v2/telemetry/ingest")
async def ingest_telemetry_batch(
    batch: TelemetryBatch,
    tenant_context: TenantContext = Depends(verify_api_signature)
):
    validate_tenant_claims(tenant_context, required_scope="telemetry:write")
    return await event_pipeline.process_events(batch.events, tenant_id=tenant_context.tenant_id)`,
    remediation: `// SECURED: API Signature Verification & Scope Validation\ntenant_context = Depends(verify_api_signature)\nvalidate_tenant_claims(tenant_context, required_scope="telemetry:write")`,
    diff_file: 'routes/telemetry.py',
    diff_before: `@app.post("/api/v2/telemetry/ingest")\nasync def ingest_telemetry_batch(batch: TelemetryBatch):\n    return await event_pipeline.process_events(batch.events)`,
    diff_after: `from sentinel_auth import verify_api_signature, validate_tenant_claims\n\n@app.post("/api/v2/telemetry/ingest")\nasync def ingest_telemetry_batch(\n    batch: TelemetryBatch,\n    tenant_context: TenantContext = Depends(verify_api_signature)\n):\n    validate_tenant_claims(tenant_context, required_scope="telemetry:write")\n    return await event_pipeline.process_events(batch.events, tenant_id=tenant_context.tenant_id)`,
    diff_reason: 'Enforces HMAC cryptographic signature verification and telemetry:write permission scopes.',
    expectedChanges:
      'Attach HMAC signature validation and tenant scope checks to telemetry endpoints to block anonymous access.',
    whyThisMatters:
      'Security telemetry ingestion routes must be strictly authenticated to prevent malicious data injection into analytics dashboards.',
    remediationSteps: [
      '1. Attach HMAC signature verification middleware to all /api/v2/telemetry routes.',
      '2. Enforce granular telemetry:write token scopes on event submission.',
      '3. Reject unauthenticated requests with HTTP 401 and log client IPs for anomaly detection.',
      '4. Enforce TLS 1.3 mutual authentication on internal ingestion gateways.',
      '5. Conduct regular automated red-team API authorization penetration tests.',
    ],
  },

  'sentinel-privilege-escalation': {
    id: 'sentinel-privilege-escalation',
    alias: 'sentinel_privilege_escalation',
    stageId: 2,
    project: 'SentinelCore',
    title: 'Privilege Escalation',
    category: 'Authorization',
    domain: 'Authorization',
    cvss: '8.8',
    cve: 'CVE-2026-7241',
    severity: 'HIGH',
    status: 'unresolved',
    description:
      'SentinelCore agent role assignment handler allows users with operator-level access to elevate their own permission scopes to cluster security administrator via unvalidated role parameter overrides.',
    attackScenario:
      'A compromised operator account modifies the JSON body in a PATCH /api/v2/users/me/roles request, setting role to "SEC_CLUSTER_ADMIN" without server-side hierarchical role boundary checks.',
    businessImpact:
      'Full takeover of SentinelCore security orchestration controls, unauthorized policy alteration, and circumvention of administrative change locks.',
    originalCode: `@router.patch("/api/v2/users/{user_id}/roles")
async def update_user_roles(user_id: str, new_roles: list[str]):
    user = await user_repo.get_by_id(user_id)
    user.roles = new_roles
    return await user_repo.save(user)`,
    patchedCode: `from sentinel_rbac import enforce_role_hierarchy, require_admin_privilege, UserRole

@router.patch("/api/v2/users/{user_id}/roles")
async def update_user_roles(
    user_id: str, 
    new_roles: list[str],
    current_user: UserContext = Depends(require_admin_privilege)
):
    enforce_role_hierarchy(current_user.roles, target_roles=new_roles)
    user = await user_repo.get_by_id(user_id)
    user.roles = new_roles
    return await user_repo.save(user)`,
    remediation: `// SECURED: Role Hierarchy Enforcement & Admin Authorization\ncurrent_user = Depends(require_admin_privilege)\nenforce_role_hierarchy(current_user.roles, target_roles=new_roles)`,
    diff_file: 'routes/users.py',
    diff_before: `@router.patch("/api/v2/users/{user_id}/roles")\nasync def update_user_roles(user_id: str, new_roles: list[str]):\n    user = await user_repo.get_by_id(user_id)\n    user.roles = new_roles\n    return await user_repo.save(user)`,
    diff_after: `from sentinel_rbac import enforce_role_hierarchy, require_admin_privilege\n\n@router.patch("/api/v2/users/{user_id}/roles")\nasync def update_user_roles(\n    user_id: str, \n    new_roles: list[str],\n    current_user: UserContext = Depends(require_admin_privilege)\n):\n    enforce_role_hierarchy(current_user.roles, target_roles=new_roles)\n    user = await user_repo.get_by_id(user_id)\n    user.roles = new_roles\n    return await user_repo.save(user)`,
    diff_reason: 'Restricts role assignments to administrators and enforces hierarchy verification.',
    expectedChanges:
      'Implement strict role hierarchy checks and restrict role updates to verified cluster administrators.',
    whyThisMatters:
      'Unchecked privilege modifications enable lateral movement and unauthorized administrative cluster takeover.',
    remediationSteps: [
      '1. Require require_admin_privilege dependency on all role management routes.',
      '2. Disallow self-modification of roles and permissions for non-superadmin accounts.',
      '3. Implement strict role hierarchy boundaries preventing operators from assigning higher roles.',
      '4. Log all role modifications to an immutable audit ledger with dual-operator approval.',
      '5. Add automated unit and integration tests verifying horizontal and vertical privilege boundaries.',
    ],
  },

  'sentinel-insecure-session-handling': {
    id: 'sentinel-insecure-session-handling',
    alias: 'sentinel_insecure_session_handling',
    stageId: 3,
    project: 'SentinelCore',
    title: 'Insecure Session Handling',
    category: 'Authentication',
    domain: 'Authentication',
    cvss: '8.2',
    cve: 'CVE-2026-6415',
    severity: 'HIGH',
    status: 'unresolved',
    description:
      'Session cookies in SentinelCore web console are issued without HttpOnly, SameSite=Strict, and Secure flags, permitting cookie extraction via client-side script contexts and cross-site scripting.',
    attackScenario:
      'An adversary leverages a cross-site script or third-party iframe to read document.cookie on an analyst workstation, capturing the active session token and impersonating the security analyst.',
    businessImpact:
      'Analyst session hijacking, unauthorized security alert acknowledgments, and covert modification of threat detection rules.',
    originalCode: `@router.post("/api/v2/auth/session")
async def create_session(response: Response, user_id: str):
    session_id = session_manager.generate_id(user_id)
    response.set_cookie(key="sentinel_session", value=session_id)
    return {"status": "authenticated"}`,
    patchedCode: `@router.post("/api/v2/auth/session")
async def create_session(response: Response, user_id: str):
    session_id = session_manager.generate_id(user_id)
    response.set_cookie(
        key="sentinel_session",
        value=session_id,
        httponly=True,
        secure=True,
        samesite="strict",
        max_age=3600
    )
    return {"status": "authenticated"}`,
    remediation: `// SECURED: Enforce Secure Cookie Flags\nresponse.set_cookie(key="sentinel_session", value=session_id, httponly=True, secure=True, samesite="strict", max_age=3600)`,
    diff_file: 'routes/auth.py',
    diff_before: `@router.post("/api/v2/auth/session")\nasync def create_session(response: Response, user_id: str):\n    session_id = session_manager.generate_id(user_id)\n    response.set_cookie(key="sentinel_session", value=session_id)\n    return {"status": "authenticated"}`,
    diff_after: `@router.post("/api/v2/auth/session")\nasync def create_session(response: Response, user_id: str):\n    session_id = session_manager.generate_id(user_id)\n    response.set_cookie(\n        key="sentinel_session",\n        value=session_id,\n        httponly=True,\n        secure=True,\n        samesite="strict",\n        max_age=3600\n    )\n    return {"status": "authenticated"}`,
    diff_reason: 'Sets HttpOnly, Secure, and SameSite=Strict flags on session authentication cookies.',
    expectedChanges:
      'Configure cryptographic session cookies with mandatory security flags and strict lifetime expiration.',
    whyThisMatters:
      'Insecure cookies expose authentication tokens to client-side exfiltration and session takeover.',
    remediationSteps: [
      '1. Set httponly=True, secure=True, and samesite="strict" on all session cookies.',
      '2. Enforce strict absolute session timeouts (max 1 hour) and idle expirations (15 minutes).',
      '3. Bind session tokens to client TLS fingerprint and IP subnet.',
      '4. Invalidate all active sessions immediately upon password reset or privilege changes.',
      '5. Deploy Content Security Policy (CSP) headers to prevent client-side script execution.',
    ],
  },

  'sentinel-sensitive-data-exposure': {
    id: 'sentinel-sensitive-data-exposure',
    alias: 'sentinel_sensitive_data_exposure',
    stageId: 4,
    project: 'SentinelCore',
    title: 'Sensitive Data Exposure',
    category: 'Data Security',
    domain: 'Data Security',
    cvss: '9.1',
    cve: 'CVE-2026-5192',
    severity: 'CRITICAL',
    status: 'unresolved',
    description:
      'SentinelCore security incident export logs include unencrypted customer PII, raw authentication tokens, and sensitive host network configurations in plain text export streams.',
    attackScenario:
      'A third-party log forwarder exports raw SentinelCore incident dump files into an external SIEM bucket where unmasked API tokens and private encryption keys are stored in unencrypted form.',
    businessImpact:
      'Violation of data privacy regulations (GDPR, HIPAA, SOC 2), credential harvesting by third-party integrations, and severe enterprise exposure.',
    originalCode: `def serialize_incident_report(incident: SecurityIncident) -> dict:
    return {
        "incident_id": incident.id,
        "host_payload": incident.raw_host_data,
        "auth_headers": incident.captured_headers,
        "pii_records": incident.affected_users
    }`,
    patchedCode: `from sentinel_privacy import redact_pii, mask_auth_headers, encrypt_host_payload

def serialize_incident_report(incident: SecurityIncident) -> dict:
    return {
        "incident_id": incident.id,
        "host_payload": encrypt_host_payload(incident.raw_host_data),
        "auth_headers": mask_auth_headers(incident.captured_headers),
        "pii_records": redact_pii(incident.affected_users)
    }`,
    remediation: `// SECURED: Field-Level Encryption & PII Redaction\n"host_payload": encrypt_host_payload(incident.raw_host_data),\n"auth_headers": mask_auth_headers(incident.captured_headers),\n"pii_records": redact_pii(incident.affected_users)`,
    diff_file: 'services/incident_exporter.py',
    diff_before: `def serialize_incident_report(incident: SecurityIncident) -> dict:\n    return {\n        "incident_id": incident.id,\n        "host_payload": incident.raw_host_data,\n        "auth_headers": incident.captured_headers,\n        "pii_records": incident.affected_users\n    }`,
    diff_after: `from sentinel_privacy import redact_pii, mask_auth_headers, encrypt_host_payload\n\ndef serialize_incident_report(incident: SecurityIncident) -> dict:\n    return {\n        "incident_id": incident.id,\n        "host_payload": encrypt_host_payload(incident.raw_host_data),\n        "auth_headers": mask_auth_headers(incident.captured_headers),\n        "pii_records": redact_pii(incident.affected_users)\n    }`,
    diff_reason: 'Encrypts host telemetry payloads and masks authentication headers and customer PII.',
    expectedChanges:
      'Apply field-level encryption and automated PII masking across all incident export serializers.',
    whyThisMatters:
      'Unmasked security log exports frequently leak credentials and confidential customer attributes to third parties.',
    remediationSteps: [
      '1. Implement automated regex masking for authentication headers and bearer tokens.',
      '2. Apply AES-256-GCM field-level encryption for sensitive host metadata payloads.',
      '3. Redact user email, phone, and identity attributes before external report serialization.',
      '4. Enforce strict data retention and cryptographic wiping policies on incident records.',
      '5. Conduct periodic compliance data scans to detect unauthorized plain-text storage.',
    ],
  },

  'sentinel-missing-rate-limiting': {
    id: 'sentinel-missing-rate-limiting',
    alias: 'sentinel_missing_rate_limiting',
    stageId: 5,
    project: 'SentinelCore',
    title: 'Missing Rate Limiting',
    category: 'API Security',
    domain: 'API Security',
    cvss: '6.5',
    cve: 'CVE-2026-4822',
    severity: 'MEDIUM',
    status: 'unresolved',
    description:
      'SentinelCore alert acknowledgement and search endpoints do not enforce client rate restrictions, allowing scripts to generate excessive database query load and cause system latency.',
    attackScenario:
      'An automated agent script sends continuous burst requests to /api/v2/alerts/query with complex regex wildcard filters, exhausting database connection pools.',
    businessImpact:
      'Degraded incident response times, latency spikes across security operations center dashboards, and infrastructure compute saturation.',
    originalCode: `@router.post("/api/v2/alerts/query")
async def query_cluster_alerts(query_filter: AlertFilter):
    return await alert_store.search(query_filter)`,
    patchedCode: `from sentinel_limiter import RateLimitGuard

rate_limit = RateLimitGuard(max_requests=100, window_seconds=60)

@router.post("/api/v2/alerts/query", dependencies=[Depends(rate_limit)])
async def query_cluster_alerts(query_filter: AlertFilter):
    return await alert_store.search(query_filter)`,
    remediation: `// SECURED: Enforce 100 req/min Rate Limiting\nrate_limit = RateLimitGuard(max_requests=100, window_seconds=60)\n@router.post("/api/v2/alerts/query", dependencies=[Depends(rate_limit)])`,
    diff_file: 'routes/alerts.py',
    diff_before: `@router.post("/api/v2/alerts/query")\nasync def query_cluster_alerts(query_filter: AlertFilter):\n    return await alert_store.search(query_filter)`,
    diff_after: `from sentinel_limiter import RateLimitGuard\n\nrate_limit = RateLimitGuard(max_requests=100, window_seconds=60)\n\n@router.post("/api/v2/alerts/query", dependencies=[Depends(rate_limit)])\nasync def query_cluster_alerts(query_filter: AlertFilter):\n    return await alert_store.search(query_filter)`,
    diff_reason: 'Restricts alert search requests to 100 queries per minute per client tenant.',
    expectedChanges:
      'Introduce Redis-backed sliding window rate limiters on resource-intensive alert search endpoints.',
    whyThisMatters:
      'Unrestricted query APIs allow resource exhaustion and denial of service on mission-critical security pipelines.',
    remediationSteps: [
      '1. Apply sliding window rate limiters (100 req/min) on heavy search and query endpoints.',
      '2. Enforce client API key tier throttling with HTTP 429 Too Many Requests responses.',
      '3. Implement query timeout caps (max 5s) to kill long-running runaway queries.',
      '4. Cache common alert filtering queries in Redis to mitigate backend load.',
      '5. Alert administrators when clients consistently exceed designated rate thresholds.',
    ],
  },

  'sentinel-weak-input-validation': {
    id: 'sentinel-weak-input-validation',
    alias: 'sentinel_weak_input_validation',
    stageId: 6,
    project: 'SentinelCore',
    title: 'Weak Input Validation',
    category: 'Application Security',
    domain: 'Application Security',
    cvss: '5.8',
    cve: 'CVE-2026-3709',
    severity: 'MEDIUM',
    status: 'unresolved',
    description:
      'SentinelCore filter rule ingestion endpoint accepts arbitrary unvalidated regular expression strings without syntax safety checks, leaving the worker process vulnerable to ReDoS attacks.',
    attackScenario:
      'An adversary submits a maliciously nested regular expression pattern `^(a+)+$` to the detection rule compiler, inducing catastrophic backtracking and pegging CPU utilization at 100%.',
    businessImpact:
      'Denial of service on background threat detection workers, halted real-time alert processing, and delayed intrusion detection.',
    originalCode: `def compile_detection_rule(pattern: str):
    return re.compile(pattern)`,
    patchedCode: `from sentinel_validator import validate_safe_regex, RegexSecurityError

def compile_detection_rule(pattern: str):
    if not validate_safe_regex(pattern, max_complexity=20):
        raise RegexSecurityError("Unsafe regex complexity detected.")
    return re.compile(pattern)`,
    remediation: `// SECURED: Safe Regex Complexity Validation\nif not validate_safe_regex(pattern, max_complexity=20):\n    raise RegexSecurityError("Unsafe regex complexity detected.")`,
    diff_file: 'rules/compiler.py',
    diff_before: `def compile_detection_rule(pattern: str):\n    return re.compile(pattern)`,
    diff_after: `from sentinel_validator import validate_safe_regex, RegexSecurityError\n\ndef compile_detection_rule(pattern: str):\n    if not validate_safe_regex(pattern, max_complexity=20):\n        raise RegexSecurityError("Unsafe regex complexity detected.")\n    return re.compile(pattern)`,
    diff_reason: 'Validates regular expression complexity and enforces maximum backtracking bounds.',
    expectedChanges:
      'Enforce regex complexity validation and execution timeouts to prevent catastrophic backtracking.',
    whyThisMatters:
      'Unvalidated regex compilation allows remote denial of service on core detection rule engines.',
    remediationSteps: [
      '1. Validate all user-supplied regex patterns using a timeout-bounded complexity validator.',
      '2. Restrict maximum regex string length to 256 characters.',
      '3. Execute detection rule evaluation inside isolated sandboxed worker processes.',
      '4. Return clear validation error messages when dangerous nested quantifiers are detected.',
      '5. Add comprehensive fuzzing and ReDoS detection test suites to CI/CD workflows.',
    ],
  },
};

export const SENTINEL_CORE_FINDINGS = Object.values(SENTINEL_CORE_THREATS);
