/**
 * AegisOne Platform Dedicated Mock Security Threat Dataset
 * 
 * Project-specific security audit findings for AegisOne Platform
 * unified cloud security posture and identity governance platform.
 */

export const AEGIS_ONE_THREATS = {
  'aegis-insecure-authentication-flow': {
    id: 'aegis-insecure-authentication-flow',
    alias: 'aegis_insecure_auth_flow',
    stageId: 1,
    project: 'AegisOne Platform',
    title: 'Insecure Authentication Flow',
    category: 'Authentication Security',
    domain: 'Authentication Security',
    cvss: '9.8',
    cve: 'CVE-2026-9215',
    severity: 'CRITICAL',
    status: 'unresolved',
    description:
      'AegisOne single sign-on (SSO) callback handlers accept unverified OAuth state parameters and skip cryptographic nonce validation, allowing adversary-in-the-middle session hijacking and unauthorized identity assumption.',
    attackScenario:
      'An attacker intercepts an OAuth 2.0 authorization redirect and injects a pre-authenticated authorization code with a spoofed state parameter into the victim session, binding the victim account to the attacker identity.',
    businessImpact:
      'Complete account takeover across enterprise client organizations, unauthorized administrative console access, and compromise of enterprise identities.',
    originalCode: `@router.get("/auth/callback")
async def oauth_callback(code: str, state: str, session: Session = Depends(get_session)):
    user_info = await idp_client.exchange_code(code)
    token = create_access_token(user_info.id)
    return {"token": token, "user": user_info}`,
    patchedCode: `from aegis_auth import verify_oauth_state, validate_pkce_verifier, AuthSecurityError

@router.get("/auth/callback")
async def oauth_callback(
    code: str,
    state: str,
    session: Session = Depends(get_session)
):
    if not verify_oauth_state(session.state_nonce, state):
        raise AuthSecurityError("Invalid or expired OAuth state parameter.")
    user_info = await idp_client.exchange_code(code, code_verifier=session.pkce_verifier)
    token = create_secure_session_token(user_info.id, tenant_id=user_info.tenant_id)
    return {"token": token, "user": user_info}`,
    remediation: `// SECURED: Cryptographic State Nonce & PKCE Code Verifier\nif not verify_oauth_state(session.state_nonce, state):\n    raise AuthSecurityError("Invalid OAuth state parameter.")`,
    diff_file: 'services/sso_handler.py',
    diff_before: `@router.get("/auth/callback")\nasync def oauth_callback(code: str, state: str):\n    user_info = await idp_client.exchange_code(code)\n    token = create_access_token(user_info.id)`,
    diff_after: `@router.get("/auth/callback")\nasync def oauth_callback(code: str, state: str, session: Session = Depends(get_session)):\n    verify_oauth_state(session.state_nonce, state)\n    user_info = await idp_client.exchange_code(code, code_verifier=session.pkce_verifier)\n    token = create_secure_session_token(user_info.id)`,
    diff_reason: 'Enforces strict cryptographic OAuth state parameter verification and PKCE code challenge validation.',
    expectedChanges:
      'Implement CSRF state token verification and PKCE code verifier checks on all OAuth/SAML authentication callbacks.',
    whyThisMatters:
      'Unvalidated OAuth state parameters leave enterprise authentication endpoints vulnerable to CSRF and account hijacking.',
    remediationSteps: [
      '1. Generate cryptographically strong, ephemeral state nonces stored in signed session cookies.',
      '2. Enforce PKCE (RFC 7636) code exchange across all OAuth 2.0 authorization flows.',
      '3. Validate state and nonce parameters before initiating token exchange with the identity provider.',
      '4. Expire authorization codes and state parameters after a maximum of 5 minutes.',
      '5. Log all authentication anomalies and state validation failures to security telemetry.',
    ],
  },

  'aegis-broken-access-control': {
    id: 'aegis-broken-access-control',
    alias: 'aegis_broken_access_control',
    stageId: 2,
    project: 'AegisOne Platform',
    title: 'Broken Access Control',
    category: 'Authorization',
    domain: 'Authorization',
    cvss: '8.9',
    cve: 'CVE-2026-8740',
    severity: 'HIGH',
    status: 'unresolved',
    description:
      'AegisOne multi-tenant policy enforcement engine permits direct object reference (IDOR) manipulation on tenant policy endpoints (/api/v2/policies/{policy_id}), allowing cross-tenant policy read and update operations.',
    attackScenario:
      'An authenticated tenant user alters the policy_id path parameter to target a competitor tenant policy, modifying security perimeter rules and granting themselves unauthorized resource access.',
    businessImpact:
      'Cross-tenant policy tampering, unauthorized rule changes, and total bypass of enterprise organizational access boundaries.',
    originalCode: `@router.put("/api/v2/policies/{policy_id}")
async def update_security_policy(policy_id: str, payload: PolicyUpdatePayload):
    policy = await policy_store.get(policy_id)
    await policy.update(payload.dict())
    return {"status": "updated", "policy": policy}`,
    patchedCode: `from aegis_rbac import verify_tenant_ownership, PolicyPermission

@router.put("/api/v2/policies/{policy_id}")
async def update_security_policy(
    policy_id: str,
    payload: PolicyUpdatePayload,
    user: AuthUser = Depends(get_authenticated_user)
):
    policy = await policy_store.get(policy_id)
    await verify_tenant_ownership(user.tenant_id, policy.tenant_id, required_scope=PolicyPermission.WRITE)
    await policy.update(payload.dict(), modified_by=user.id)
    return {"status": "updated", "policy": policy}`,
    remediation: `// SECURED: Tenant Ownership & Policy Permission Scoping\nawait verify_tenant_ownership(user.tenant_id, policy.tenant_id, required_scope=PolicyPermission.WRITE)`,
    diff_file: 'controllers/policy_engine.py',
    diff_before: `@router.put("/api/v2/policies/{policy_id}")\nasync def update_security_policy(policy_id: str, payload: PolicyUpdatePayload):\n    policy = await policy_store.get(policy_id)\n    await policy.update(payload.dict())`,
    diff_after: `@router.put("/api/v2/policies/{policy_id}")\nasync def update_security_policy(policy_id: str, payload: PolicyUpdatePayload, user: AuthUser = Depends(get_authenticated_user)):\n    policy = await policy_store.get(policy_id)\n    await verify_tenant_ownership(user.tenant_id, policy.tenant_id, required_scope=PolicyPermission.WRITE)\n    await policy.update(payload.dict())`,
    diff_reason: 'Verifies tenant ownership and role-based permissions before allowing security policy mutations.',
    expectedChanges:
      'Enforce tenant ownership verification and granular RBAC checks on all parameterized policy modification routes.',
    whyThisMatters:
      'Without object-level authorization, users can tamper with policies belonging to other organizations.',
    remediationSteps: [
      '1. Implement mandatory tenant ownership validation middleware on all resource controllers.',
      '2. Reject cross-tenant object ID queries with HTTP 403 Forbidden.',
      '3. Enforce policy write permissions at both the API gateway and data repository layers.',
      '4. Add automated multi-tenant isolation unit tests to CI/CD pipelines.',
      '5. Audit all policy modification history with immutable tenant attribution.',
    ],
  },

  'aegis-sensitive-customer-data-exposure': {
    id: 'aegis-sensitive-customer-data-exposure',
    alias: 'aegis_sensitive_data_exposure',
    stageId: 3,
    project: 'AegisOne Platform',
    title: 'Sensitive Customer Data Exposure',
    category: 'Data Security',
    domain: 'Data Security',
    cvss: '9.3',
    cve: 'CVE-2026-9133',
    severity: 'CRITICAL',
    status: 'unresolved',
    description:
      'AegisOne diagnostic report exports and telemetry dumps return unmasked customer Personally Identifiable Information (PII), credit card billing details, and unencrypted session tokens in plain-text API responses.',
    attackScenario:
      'An unauthorized actor queries the system diagnostics endpoint /api/v1/diagnostics/export and receives full customer database records containing unmasked PII, email addresses, and active API tokens.',
    businessImpact:
      'Severe GDPR/CCPA regulatory fines, customer data exfiltration, reputational catastrophe, and loss of enterprise certifications.',
    originalCode: `@router.get("/api/v1/diagnostics/export")
async def export_diagnostic_data(tenant_id: str):
    records = await customer_db.fetch_all_records(tenant_id)
    return {"status": "ok", "records": records}`,
    patchedCode: `from aegis_privacy import mask_pii_fields, RedactionProfile

@router.get("/api/v1/diagnostics/export")
async def export_diagnostic_data(
    tenant_id: str,
    user: AuthUser = Depends(get_authenticated_user)
):
    await require_admin_privileges(user, tenant_id)
    records = await customer_db.fetch_all_records(tenant_id)
    sanitized_records = mask_pii_fields(records, profile=RedactionProfile.STRICT_PII_REDACTION)
    return {"status": "ok", "records": sanitized_records}`,
    remediation: `// SECURED: Automatic PII Masking & Admin Authorization\nsanitized_records = mask_pii_fields(records, profile=RedactionProfile.STRICT_PII_REDACTION)`,
    diff_file: 'api/diagnostics.py',
    diff_before: `@router.get("/api/v1/diagnostics/export")\nasync def export_diagnostic_data(tenant_id: str):\n    records = await customer_db.fetch_all_records(tenant_id)\n    return {"status": "ok", "records": records}`,
    diff_after: `@router.get("/api/v1/diagnostics/export")\nasync def export_diagnostic_data(tenant_id: str, user: AuthUser = Depends(get_authenticated_user)):\n    await require_admin_privileges(user, tenant_id)\n    records = await customer_db.fetch_all_records(tenant_id)\n    sanitized = mask_pii_fields(records, profile=RedactionProfile.STRICT_PII_REDACTION)\n    return {"status": "ok", "records": sanitized}`,
    diff_reason: 'Applies strict PII field masking and requires administrative privileges for diagnostic exports.',
    expectedChanges:
      'Enforce automatic PII redaction (email, SSN, tokens) in all diagnostic endpoints and telemetry payloads.',
    whyThisMatters:
      'Exposing raw customer data in diagnostic routes violates data privacy regulations and risks mass data theft.',
    remediationSteps: [
      '1. Implement automated PII scrubbing middleware across all telemetry and export endpoints.',
      '2. Restrict export routes strictly to authorized tenant security administrators.',
      '3. Encrypt diagnostic dumps with tenant-specific public keys before storage or transmission.',
      '4. Conduct automated static code scans for unmasked database field serializations.',
      '5. Maintain compliance audits for GDPR Article 32 and CCPA data privacy requirements.',
    ],
  },

  'aegis-missing-api-rate-limiting': {
    id: 'aegis-missing-api-rate-limiting',
    alias: 'aegis_missing_api_rate_limiting',
    stageId: 4,
    project: 'AegisOne Platform',
    title: 'Missing API Rate Limiting',
    category: 'API Security',
    domain: 'API Security',
    cvss: '7.6',
    cve: 'CVE-2026-6819',
    severity: 'HIGH',
    status: 'unresolved',
    description:
      'AegisOne security event webhook ingestion and user authentication routes lack request throttling and rate limiting, leaving services susceptible to denial of service (DoS) and credential brute-force attacks.',
    attackScenario:
      'An adversary floods the /api/v1/events/ingest endpoint with 100,000 requests per minute from a distributed botnet, saturating database connection pools and causing system-wide service degradation.',
    businessImpact:
      'Platform outages, denial of service for legitimate tenants, cloud infrastructure cost spikes, and vulnerability to brute-force authentication attacks.',
    originalCode: `@router.post("/api/v1/events/ingest")
async def ingest_security_event(event: SecurityEventPayload):
    await event_processor.process(event)
    return {"status": "accepted"}`,
    patchedCode: `from aegis_limiter import rate_limit, TokenBucketLimiter

@router.post("/api/v1/events/ingest")
@rate_limit(limit="120/minute", key_func=TokenBucketLimiter.get_client_ip_and_tenant)
async def ingest_security_event(
    request: Request,
    event: SecurityEventPayload
):
    await event_processor.process(event)
    return {"status": "accepted"}`,
    remediation: `// SECURED: Token Bucket Rate Limiting (120 req/min per tenant)\n@rate_limit(limit="120/minute", key_func=TokenBucketLimiter.get_client_ip_and_tenant)`,
    diff_file: 'routes/event_ingress.py',
    diff_before: `@router.post("/api/v1/events/ingest")\nasync def ingest_security_event(event: SecurityEventPayload):\n    await event_processor.process(event)`,
    diff_after: `@router.post("/api/v1/events/ingest")\n@rate_limit(limit="120/minute", key_func=TokenBucketLimiter.get_client_ip_and_tenant)\nasync def ingest_security_event(request: Request, event: SecurityEventPayload):\n    await event_processor.process(event)`,
    diff_reason: 'Attaches token bucket rate limiting middleware to prevent volumetric DoS and abuse.',
    expectedChanges:
      'Deploy adaptive Redis-backed rate limiting across all public ingestion and authentication APIs.',
    whyThisMatters:
      'Rate limiting protects platform availability, controls compute costs, and prevents automated brute-force attacks.',
    remediationSteps: [
      '1. Configure distributed Redis token bucket rate limiting on all public API routes.',
      '2. Enforce tiered rate limits based on client IP and tenant subscription tier.',
      '3. Return standard HTTP 429 Too Many Requests with Retry-After headers.',
      '4. Set up real-time alarms for tenants exceeding 80% of their allocated rate limit quota.',
      '5. Implement Cloudflare/AWS WAF rate-limiting rules at the ingress edge layer.',
    ],
  },

  'aegis-unsafe-input-handling': {
    id: 'aegis-unsafe-input-handling',
    alias: 'aegis_unsafe_input_handling',
    stageId: 5,
    project: 'AegisOne Platform',
    title: 'Unsafe Input Handling',
    category: 'Application Security',
    domain: 'Application Security',
    cvss: '6.5',
    cve: 'CVE-2026-5782',
    severity: 'MEDIUM',
    status: 'unresolved',
    description:
      'AegisOne rule evaluation engine dynamically compiles user-supplied regex filters and query expressions without syntax validation or length constraints, leading to Regular Expression Denial of Service (ReDoS).',
    attackScenario:
      'A malicious operator configures a custom rule filter containing catastrophic backtracking regex ((a+)+)$, which locks worker CPU cores at 100% utilization during rule matching runs.',
    businessImpact:
      'Thread starvation on rule evaluation workers, delayed threat detection alerts, and intermittent container crashes.',
    originalCode: `def compile_custom_filter(raw_regex: str) -> re.Pattern:
    return re.compile(raw_regex)`,
    patchedCode: `import re2
from aegis_validators import validate_regex_safety, FilterSyntaxException

def compile_custom_filter(raw_regex: str) -> re2.Pattern:
    if len(raw_regex) > 500:
        raise FilterSyntaxException("Filter expression exceeds maximum 500 character length.")
    validate_regex_safety(raw_regex)
    return re2.compile(raw_regex, options=re2.Options(max_mem=8<<20))`,
    remediation: `// SECURED: Linear-Time RE2 Safe Regex Compilation\nvalidate_regex_safety(raw_regex)\nreturn re2.compile(raw_regex, options=re2.Options(max_mem=8<<20))`,
    diff_file: 'rules/filter_compiler.py',
    diff_before: `def compile_custom_filter(raw_regex: str) -> re.Pattern:\n    return re.compile(raw_regex)`,
    diff_after: `def compile_custom_filter(raw_regex: str) -> re2.Pattern:\n    validate_regex_safety(raw_regex)\n    return re2.compile(raw_regex, options=re2.Options(max_mem=8<<20))`,
    diff_reason: 'Replaces backtracking Python regex engine with linear-time Google RE2 compiler and expression length limits.',
    expectedChanges:
      'Migrate regex compilation to Google RE2 with strict length bounds to eliminate catastrophic backtracking.',
    whyThisMatters:
      'Unchecked user-supplied regular expressions can cause CPU lockups and stall real-time detection engines.',
    remediationSteps: [
      '1. Replace standard Python re engine with Google RE2 for all user-defined pattern matching.',
      '2. Enforce a strict 500-character upper limit on custom filter expressions.',
      '3. Analyze regex AST for nested quantifiers and reject exponential complexity patterns.',
      '4. Set execution timeouts (max 50ms) on all runtime filter evaluation loops.',
      '5. Add automated ReDoS fuzzing suites to the security regression test harness.',
    ],
  },

  'aegis-insufficient-security-logging': {
    id: 'aegis-insufficient-security-logging',
    alias: 'aegis_insufficient_security_logging',
    stageId: 6,
    project: 'AegisOne Platform',
    title: 'Insufficient Security Logging',
    category: 'Monitoring & Logging',
    domain: 'Monitoring & Logging',
    cvss: '5.2',
    cve: 'CVE-2026-4428',
    severity: 'MEDIUM',
    status: 'unresolved',
    description:
      'AegisOne administrative role assignments, API key revocations, and firewall rule modifications are executed silently without generating immutable audit log records or SIEM forwarding.',
    attackScenario:
      'A rogue administrator assigns superuser permissions to a backdoor account and deletes an active firewall policy, leaving zero audit evidence in the security management ledger.',
    businessImpact:
      'Undetected administrative tampering, inability to establish non-repudiation in breach forensics, and failure of SOC 2 Type II audit controls.',
    originalCode: `async def update_admin_role(target_user_id: str, new_role: str):
    await user_repository.set_role(target_user_id, new_role)
    return {"status": "success"}`,
    patchedCode: `from aegis_audit import emit_audit_event, AuditLevel

async def update_admin_role(
    target_user_id: str,
    new_role: str,
    actor_id: str,
    actor_ip: str
):
    old_role = await user_repository.get_role(target_user_id)
    await user_repository.set_role(target_user_id, new_role)
    await emit_audit_event(
        action="ROLE_ASSIGNMENT_CHANGED",
        level=AuditLevel.HIGH,
        details={
            "target_user": target_user_id,
            "old_role": old_role,
            "new_role": new_role,
            "actor": actor_id,
            "ip_address": actor_ip,
            "timestamp": get_utc_timestamp()
        }
    )
    return {"status": "success"}`,
    remediation: `// SECURED: Structured Audit Event Logging to SIEM\nawait emit_audit_event(action="ROLE_ASSIGNMENT_CHANGED", details={"target_user": target_user_id, "new_role": new_role, "actor": actor_id})`,
    diff_file: 'services/role_manager.py',
    diff_before: `async def update_admin_role(target_user_id: str, new_role: str):\n    await user_repository.set_role(target_user_id, new_role)`,
    diff_after: `async def update_admin_role(target_user_id: str, new_role: str, actor_id: str, actor_ip: str):\n    await user_repository.set_role(target_user_id, new_role)\n    await emit_audit_event("ROLE_ASSIGNMENT_CHANGED", details={"target": target_user_id, "role": new_role, "actor": actor_id})`,
    diff_reason: 'Emits structured immutable audit log events for all administrative role and privilege modifications.',
    expectedChanges:
      'Implement mandatory structured audit logging for all privilege changes and security policy alterations.',
    whyThisMatters:
      'Audit logging is crucial for forensic investigations, compliance verification, and detecting insider threats.',
    remediationSteps: [
      '1. Instrument all administrative role mutation endpoints with structured audit event emitters.',
      '2. Include actor identity, client IP address, timestamp, previous state, and new state in log events.',
      '3. Forward all security audit events immediately to an immutable centralized SIEM.',
      '4. Configure automated high-severity alerts for privilege escalation events.',
      '5. Retain audit logs in write-once-read-many (WORM) storage for a minimum of 1 year.',
    ],
  },
};

export const AEGIS_ONE_FINDINGS = Object.values(AEGIS_ONE_THREATS);
