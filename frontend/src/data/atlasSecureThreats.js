/**
 * Atlas Secure Systems Dedicated Mock Security Threat Dataset
 * 
 * Project-specific security audit findings for Atlas Secure Systems
 * enterprise Zero-Trust infrastructure and cryptographic identity platform.
 */

export const ATLAS_SECURE_THREATS = {
  'atlas-insecure-deserialization': {
    id: 'atlas-insecure-deserialization',
    alias: 'atlas_insecure_deserialization',
    stageId: 1,
    project: 'Atlas Secure Systems',
    title: 'Insecure Deserialization in State Sync',
    category: 'Application Security',
    domain: 'Application Security',
    cvss: '9.6',
    cve: 'CVE-2026-9382',
    severity: 'CRITICAL',
    status: 'unresolved',
    description:
      'Atlas Secure Systems distributed cluster state synchronization protocol accepts raw pickled Python payloads over peer gossip channels without cryptographic validation or type whitelisting, permitting arbitrary remote code execution.',
    attackScenario:
      'An adversary connected to the internal node mesh sends a crafted pickle bytecode payload to the cluster gossip listener at port 8443, executing shell commands with cluster root privileges.',
    businessImpact:
      'Total compromise of all Atlas Zero-Trust mesh gateways, arbitrary host execution, and unauthorized interception of encrypted node-to-node tunnels.',
    originalCode: `async def receive_node_state(raw_stream: bytes):
    state_payload = pickle.loads(raw_stream)
    return await cluster_mesh.apply_sync(state_payload)`,
    patchedCode: `from atlas_security import safe_json_schema_load, verify_peer_hmac, StateSyncSchema

async def receive_node_state(raw_stream: bytes, peer_sig: str, peer_key: str):
    verify_peer_hmac(raw_stream, signature=peer_sig, secret_key=peer_key)
    state_payload = safe_json_schema_load(raw_stream, schema=StateSyncSchema)
    return await cluster_mesh.apply_sync(state_payload)`,
    remediation: `// SECURED: Peer HMAC Verification & Strict JSON Schema Validation\nverify_peer_hmac(raw_stream, signature=peer_sig, secret_key=peer_key)\nstate_payload = safe_json_schema_load(raw_stream, schema=StateSyncSchema)`,
    diff_file: 'mesh/gossip_sync.py',
    diff_before: `async def receive_node_state(raw_stream: bytes):\n    state_payload = pickle.loads(raw_stream)\n    return await cluster_mesh.apply_sync(state_payload)`,
    diff_after: `from atlas_security import safe_json_schema_load, verify_peer_hmac, StateSyncSchema\n\nasync def receive_node_state(raw_stream: bytes, peer_sig: str, peer_key: str):\n    verify_peer_hmac(raw_stream, signature=peer_sig, secret_key=peer_key)\n    state_payload = safe_json_schema_load(raw_stream, schema=StateSyncSchema)\n    return await cluster_mesh.apply_sync(state_payload)`,
    diff_reason: 'Replaces unsafe pickle deserialization with HMAC peer validation and strict JSON schema parsing.',
    expectedChanges:
      'Enforce cryptographic HMAC signature checks on mesh peer streams and reject non-JSON binary payloads.',
    whyThisMatters:
      'Insecure deserialization allows unauthenticated attackers to execute arbitrary system commands within cluster boundaries.',
    remediationSteps: [
      '1. Remove pickle.loads and replace with strict typed JSON schema deserialization.',
      '2. Enforce peer node HMAC signature authentication on all mesh gossip streams.',
      '3. Drop unauthorized peer connection attempts immediately with security audit alerts.',
      '4. Isolate cluster synchronization listeners within sandboxed Linux network namespaces.',
      '5. Add automated fuzzing tests for peer mesh protocol parsing in CI/CD.',
    ],
  },

  'atlas-improper-token-verification': {
    id: 'atlas-improper-token-verification',
    alias: 'atlas_improper_token_verification',
    stageId: 2,
    project: 'Atlas Secure Systems',
    title: 'Improper Zero-Trust Token Verification',
    category: 'Identity & Access',
    domain: 'Identity & Access',
    cvss: '8.7',
    cve: 'CVE-2026-8104',
    severity: 'HIGH',
    status: 'unresolved',
    description:
      'The Zero-Trust boundary ingress proxy evaluates JWT tokens using the insecure "none" algorithm and fails to validate token expiration timestamps when upstream cluster clocks skew.',
    attackScenario:
      'An attacker modifies an expired client authorization JWT, sets the algorithm header to "none", strips the signature block, and submits it to /api/v3/gateway/access, gaining unauthenticated resource access.',
    businessImpact:
      'Bypass of Zero-Trust access perimeter, unauthorized client access to internal microservices, and nullification of identity verification guards.',
    originalCode: `@router.post("/api/v3/gateway/access")
async def verify_gateway_access(token: str = Header(...)):
    claims = jwt.decode(token, options={"verify_signature": False})
    return await proxy_request(claims.get("target_service"))`,
    patchedCode: `from atlas_auth import verify_strict_jwt, AtlasSecurityException

@router.post("/api/v3/gateway/access")
async def verify_gateway_access(token: str = Header(...)):
    claims = verify_strict_jwt(
        token,
        allowed_algorithms=["RS256", "ES384"],
        require_expiry=True,
        clock_skew_sec=30
    )
    return await proxy_request(claims.get("target_service"))`,
    remediation: `// SECURED: Strict Asymmetric JWT Validation\nclaims = verify_strict_jwt(token, allowed_algorithms=["RS256", "ES384"], require_expiry=True, clock_skew_sec=30)`,
    diff_file: 'proxy/ingress_guard.py',
    diff_before: `@router.post("/api/v3/gateway/access")\nasync def verify_gateway_access(token: str = Header(...)):\n    claims = jwt.decode(token, options={"verify_signature": False})\n    return await proxy_request(claims.get("target_service"))`,
    diff_after: `from atlas_auth import verify_strict_jwt\n\n@router.post("/api/v3/gateway/access")\nasync def verify_gateway_access(token: str = Header(...)):\n    claims = verify_strict_jwt(token, allowed_algorithms=["RS256", "ES384"], require_expiry=True)\n    return await proxy_request(claims.get("target_service"))`,
    diff_reason: 'Enforces strict asymmetric RS256/ES384 signature verification and strict expiration checks.',
    expectedChanges:
      'Reject unsigned tokens, restrict valid signing algorithms to RS256/ES384, and enforce expiration timestamps.',
    whyThisMatters:
      'Zero-Trust access policies are ineffective if ingress gateways fail to cryptographically verify token authenticity.',
    remediationSteps: [
      '1. Explicitly disallow algorithm "none" and enforce RS256 or ES384 signatures.',
      '2. Validate exp, nbf, and iat claims with bounded 30-second clock skew tolerance.',
      '3. Verify token issuer (iss) and audience (aud) against known cluster authority certificates.',
      '4. Rotate public verification keys dynamically from the Atlas Key Orchestrator.',
      '5. Log all signature validation failures to the security operations center.',
    ],
  },

  'atlas-cryptographic-key-flaw': {
    id: 'atlas-cryptographic-key-flaw',
    alias: 'atlas_cryptographic_key_flaw',
    stageId: 3,
    project: 'Atlas Secure Systems',
    title: 'Cryptographic Key Permutation Flaw',
    category: 'Cryptography',
    domain: 'Cryptography',
    cvss: '9.2',
    cve: 'CVE-2026-7491',
    severity: 'CRITICAL',
    status: 'unresolved',
    description:
      'Atlas Secure Systems envelope encryption helper reuses static Initialization Vectors (IVs) with AES-GCM across multiple data blocks, enabling ciphertext analysis and nonce-reuse key recovery.',
    attackScenario:
      'An attacker collecting encrypted backup blobs across multiple backup intervals detects identical IV values, computing the authentication key via polynomial arithmetic and decrypting master customer keys.',
    businessImpact:
      'Catastrophic compromise of AES master encryption keys, exposure of all encrypted data records, and complete loss of cryptographic confidentiality.',
    originalCode: `def encrypt_data_envelope(data: bytes, key: bytes) -> bytes:
    static_iv = b"ATLAS_STATIC_IV_"
    cipher = AES.new(key, AES.MODE_GCM, nonce=static_iv)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return static_iv + tag + ciphertext`,
    patchedCode: `import os
from Crypto.Cipher import AES

def encrypt_data_envelope(data: bytes, key: bytes) -> bytes:
    random_iv = os.urandom(12)  # NIST recommended 96-bit CSPRNG nonce
    cipher = AES.new(key, AES.MODE_GCM, nonce=random_iv)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return random_iv + tag + ciphertext`,
    remediation: `// SECURED: CSPRNG Random Nonce Generation\nrandom_iv = os.urandom(12)\ncipher = AES.new(key, AES.MODE_GCM, nonce=random_iv)`,
    diff_file: 'crypto/envelope.py',
    diff_before: `def encrypt_data_envelope(data: bytes, key: bytes) -> bytes:\n    static_iv = b"ATLAS_STATIC_IV_"\n    cipher = AES.new(key, AES.MODE_GCM, nonce=static_iv)\n    ciphertext, tag = cipher.encrypt_and_digest(data)\n    return static_iv + tag + ciphertext`,
    diff_after: `import os\nfrom Crypto.Cipher import AES\n\ndef encrypt_data_envelope(data: bytes, key: bytes) -> bytes:\n    random_iv = os.urandom(12)\n    cipher = AES.new(key, AES.MODE_GCM, nonce=random_iv)\n    ciphertext, tag = cipher.encrypt_and_digest(data)\n    return random_iv + tag + ciphertext`,
    diff_reason: 'Replaces static IV reuse with cryptographically secure 96-bit CSPRNG nonces per encryption call.',
    expectedChanges:
      'Generate unique 96-bit random nonces via os.urandom for every AES-GCM encryption operation.',
    whyThisMatters:
      'Nonce reuse in AES-GCM destroys confidentiality and allows attackers to recover authentication subkeys.',
    remediationSteps: [
      '1. Utilize os.urandom(12) to generate unique 96-bit nonces for every encryption operation.',
      '2. Prepend unique nonces to the ciphertext output stream for decryption recovery.',
      '3. Re-encrypt historical data blobs that were encrypted using static IVs.',
      '4. Implement automated key rotation via AWS KMS or HashiCorp Vault.',
      '5. Add automated static cryptographic lint checks in the code review pipeline.',
    ],
  },

  'atlas-unrestricted-microsegmentation': {
    id: 'atlas-unrestricted-microsegmentation',
    alias: 'atlas_unrestricted_microsegmentation',
    stageId: 4,
    project: 'Atlas Secure Systems',
    title: 'Unrestricted Internal Microsegmentation',
    category: 'Network Security',
    domain: 'Network Security',
    cvss: '8.1',
    cve: 'CVE-2026-6630',
    severity: 'HIGH',
    status: 'unresolved',
    description:
      'Atlas internal service-to-service communication defaults to an open mesh routing topology where unprivileged gateway pods can query sensitive Hardware Security Module (HSM) control ports directly.',
    attackScenario:
      'An attacker who compromises a perimeter reporting pod issues direct RPC commands across the open internal network to the HSM management interface on port 9090, extracting key derivation policies.',
    businessImpact:
      'Lateral movement across the internal service mesh, unauthorized access to HSM key policies, and escalation of blast radius.',
    originalCode: `# mesh_policy.yaml — permissive default routing
apiVersion: security.atlas/v1
kind: MeshPolicy
spec:
  defaultAction: ALLOW_ALL
  egressRules:
    - destination: "*:*"`,
    patchedCode: `# mesh_policy.yaml — strict default-deny microsegmentation
apiVersion: security.atlas/v1
kind: MeshPolicy
spec:
  defaultAction: DENY_ALL
  egressRules:
    - destination: "hsm-service.internal:9090"
      allowedCallers: ["key-orchestrator.internal"]
      enforceMTLS: true`,
    remediation: `// SECURED: Default-Deny Network Segmentation Policy\ndefaultAction: DENY_ALL\negressRules:\n  - destination: "hsm-service.internal:9090"\n    allowedCallers: ["key-orchestrator.internal"]\n    enforceMTLS: true`,
    diff_file: 'config/mesh_policy.yaml',
    diff_before: `apiVersion: security.atlas/v1\nkind: MeshPolicy\nspec:\n  defaultAction: ALLOW_ALL\n  egressRules:\n    - destination: "*:*"`,
    diff_after: `apiVersion: security.atlas/v1\nkind: MeshPolicy\nspec:\n  defaultAction: DENY_ALL\n  egressRules:\n    - destination: "hsm-service.internal:9090"\n      allowedCallers: ["key-orchestrator.internal"]\n      enforceMTLS: true`,
    diff_reason: 'Enforces strict default-deny microsegmentation and restricts HSM access to key orchestrators.',
    expectedChanges:
      'Deploy default-deny network policies and restrict HSM management port access to explicitly whitelisted callers with mTLS.',
    whyThisMatters:
      'Microsegmentation contains lateral movement and protects critical cryptographic infrastructure from perimeter compromises.',
    remediationSteps: [
      '1. Implement default-deny network segmentation policies across all Kubernetes namespaces.',
      '2. Restrict HSM port 9090 access strictly to the Key Orchestrator service account.',
      '3. Enforce mTLS encryption and mutual certificate validation on all inter-pod traffic.',
      '4. Maintain continuous automated traffic flow mapping to detect anomalous internal calls.',
      '5. Run automated network policy conformance tests on every cluster deployment.',
    ],
  },

  'atlas-audit-log-tampering': {
    id: 'atlas-audit-log-tampering',
    alias: 'atlas_audit_log_tampering',
    stageId: 5,
    project: 'Atlas Secure Systems',
    title: 'Audit Log Tampering Vulnerability',
    category: 'Compliance & Audit',
    domain: 'Compliance & Audit',
    cvss: '6.4',
    cve: 'CVE-2026-5381',
    severity: 'MEDIUM',
    status: 'unresolved',
    description:
      'Atlas Secure Systems audit logging engine writes security events to mutable local disk files without forward-secure cryptographic hashing or write-once append locks, allowing log modification.',
    attackScenario:
      'A local system user with elevated container privileges edits /var/log/atlas/audit.log to purge entries documenting their unauthorized key export attempts before log ingestion cycles.',
    businessImpact:
      'Destruction of forensic evidence, failure to meet SOC 2 / ISO 27001 audit compliance mandates, and inability to reconstruct security incident timelines.',
    originalCode: `def append_audit_event(event: dict):
    with open("/var/log/atlas/audit.log", "a") as f:
        f.write(json.dumps(event) + "\\n")`,
    patchedCode: `from atlas_audit import sign_and_ship_event, ImmutableLogLedger

def append_audit_event(event: dict):
    signed_event = ImmutableLogLedger.sign_with_hmac_chain(event)
    return sign_and_ship_event(signed_event, destination="s3://atlas-immutable-audit-vault")`,
    remediation: `// SECURED: HMAC Chained Immutable Audit Logging\nsigned_event = ImmutableLogLedger.sign_with_hmac_chain(event)\nsign_and_ship_event(signed_event, destination="s3://atlas-immutable-audit-vault")`,
    diff_file: 'audit/logger.py',
    diff_before: `def append_audit_event(event: dict):\n    with open("/var/log/atlas/audit.log", "a") as f:\n        f.write(json.dumps(event) + "\\n")`,
    diff_after: `from atlas_audit import sign_and_ship_event, ImmutableLogLedger\n\ndef append_audit_event(event: dict):\n    signed_event = ImmutableLogLedger.sign_with_hmac_chain(event)\n    return sign_and_ship_event(signed_event, destination="s3://atlas-immutable-audit-vault")`,
    diff_reason: 'Implements HMAC hash-chaining and ships signed audit events to an immutable remote S3 object vault.',
    expectedChanges:
      'Implement HMAC hash-chained log integrity and stream security audit events to immutable WORM storage.',
    whyThisMatters:
      'Tamper-evident audit logging is essential for forensic investigation and regulatory compliance integrity.',
    remediationSteps: [
      '1. Implement forward-secure HMAC hash chaining on all audit log records.',
      '2. Stream audit events immediately to an immutable Write-Once-Read-Many (WORM) cloud repository.',
      '3. Restrict local disk log access to read-only for all application service accounts.',
      '4. Implement automated integrity verification alarms for broken cryptographic log chains.',
      '5. Retain immutable security audit logs for a minimum of 365 days in compliance with standards.',
    ],
  },

  'atlas-unbounded-session-allocation': {
    id: 'atlas-unbounded-session-allocation',
    alias: 'atlas_unbounded_session_allocation',
    stageId: 6,
    project: 'Atlas Secure Systems',
    title: 'Unbounded Concurrent Session Allocation',
    category: 'Resource Management',
    domain: 'Resource Management',
    cvss: '5.9',
    cve: 'CVE-2026-4190',
    severity: 'MEDIUM',
    status: 'unresolved',
    description:
      'Atlas Zero-Trust access gateway does not enforce maximum concurrent session limits per user, allowing single credentials to spawn thousands of active proxy tunnels and exhaust server file descriptors.',
    attackScenario:
      'A script utilizing compromised service account credentials opens 50,000 idle TLS proxy sessions simultaneously against the Atlas Gateway, exhausting socket handles and causing connection drops for legitimate users.',
    businessImpact:
      'Denial of service for legitimate enterprise operators, memory exhaustion on ingress gateway nodes, and resource starvation.',
    originalCode: `async def allocate_proxy_session(user_id: str, client_ip: str):
    session = ProxySession(user_id=user_id, ip=client_ip)
    await active_sessions.register(session)
    return session`,
    patchedCode: `from atlas_limits import enforce_session_quota, SessionQuotaExceeded

async def allocate_proxy_session(user_id: str, client_ip: str):
    if await active_sessions.count_for_user(user_id) >= 10:
        raise SessionQuotaExceeded("Max concurrent sessions (10) exceeded for user.")
    session = ProxySession(user_id=user_id, ip=client_ip)
    await active_sessions.register(session)
    return session`,
    remediation: `// SECURED: Max 10 Concurrent Sessions Quota Enforcement\nif await active_sessions.count_for_user(user_id) >= 10:\n    raise SessionQuotaExceeded("Max concurrent sessions (10) exceeded for user.")`,
    diff_file: 'gateway/session_pool.py',
    diff_before: `async def allocate_proxy_session(user_id: str, client_ip: str):\n    session = ProxySession(user_id=user_id, ip=client_ip)\n    await active_sessions.register(session)\n    return session`,
    diff_after: `from atlas_limits import enforce_session_quota, SessionQuotaExceeded\n\nasync def allocate_proxy_session(user_id: str, client_ip: str):\n    if await active_sessions.count_for_user(user_id) >= 10:\n        raise SessionQuotaExceeded("Max concurrent sessions (10) exceeded for user.")\n    session = ProxySession(user_id=user_id, ip=client_ip)\n    await active_sessions.register(session)\n    return session`,
    diff_reason: 'Limits concurrent proxy sessions to 10 per user account to prevent resource exhaustion.',
    expectedChanges:
      'Enforce a strict quota of 10 concurrent active sessions per user account and reject excess connection allocations.',
    whyThisMatters:
      'Unbounded session allocation allows malicious or compromised accounts to exhaust network socket pools.',
    remediationSteps: [
      '1. Implement user session quota enforcement (max 10 concurrent active sessions).',
      '2. Automatically reap idle proxy sessions exceeding 15 minutes of inactivity.',
      '3. Return clear HTTP 429 / Quota Exceeded error notifications to clients.',
      '4. Monitor active socket descriptors on Atlas gateway proxy nodes.',
      '5. Add automated load tests verifying session throttling under high concurrency.',
    ],
  },
};

export const ATLAS_SECURE_FINDINGS = Object.values(ATLAS_SECURE_THREATS);
