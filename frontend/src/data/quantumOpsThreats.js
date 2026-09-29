/**
 * QuantumOps Dedicated Mock Security Threat Dataset
 * 
 * Project-specific security audit findings for QuantumOps
 * hybrid quantum computing orchestration and workload scheduling platform.
 */

export const QUANTUM_OPS_THREATS = {
  'quantum-api-key-exposure': {
    id: 'quantum-api-key-exposure',
    alias: 'quantum_api_key_exposure',
    stageId: 1,
    project: 'QuantumOps',
    title: 'API Key Exposure',
    category: 'Secrets Security',
    domain: 'Secrets Security',
    cvss: '9.5',
    cve: 'CVE-2026-9501',
    severity: 'CRITICAL',
    status: 'unresolved',
    description:
      'QuantumOps cloud provider integration services contain hardcoded API master keys and quantum hardware execution tokens within application source files and client headers, exposing access to quantum computing clusters.',
    attackScenario:
      'An external attacker inspects client configuration bundles and discovers hardcoded QPU access keys, allowing unauthorized scheduling of expensive quantum annealing jobs and extraction of proprietary quantum circuit results.',
    businessImpact:
      'Massive cloud computing costs, compromise of quantum provider accounts, and unauthorized access to proprietary quantum simulation algorithms and cryptographic research.',
    originalCode: `QUANTUM_PROVIDER_API_KEY = "qp_live_9f82d1c7a8b4e3f21900a"

async def connect_qpu_cluster():
    client = QuantumClient(api_key=QUANTUM_PROVIDER_API_KEY)
    return await client.initialize_session()`,
    patchedCode: `import os
from quantum_vault import SecretManager

async def connect_qpu_cluster():
    api_key = os.getenv("QUANTUM_PROVIDER_API_KEY") or await SecretManager.get_secret("QPU_API_KEY")
    if not api_key:
        raise ValueError("Missing QPU API credentials in secure environment")
    client = QuantumClient(api_key=api_key)
    return await client.initialize_session()`,
    remediation: `// SECURED: Environment Secrets Manager Injection\napi_key = os.getenv("QUANTUM_PROVIDER_API_KEY") or await SecretManager.get_secret("QPU_API_KEY")`,
    diff_file: 'services/qpu_connector.py',
    diff_before: `QUANTUM_PROVIDER_API_KEY = "qp_live_9f82d1c7a8b4e3f21900a"\n\nasync def connect_qpu_cluster():\n    client = QuantumClient(api_key=QUANTUM_PROVIDER_API_KEY)`,
    diff_after: `from quantum_vault import SecretManager\n\nasync def connect_qpu_cluster():\n    api_key = await SecretManager.get_secret("QPU_API_KEY")\n    client = QuantumClient(api_key=api_key)`,
    diff_reason: 'Replaces hardcoded provider credentials with dynamic secret retrieval from secure vault.',
    expectedChanges:
      'Extract hardcoded QPU tokens into environment variables and integrate automated secret rotation with Vault.',
    whyThisMatters:
      'Hardcoded API credentials in source repositories risk immediate compromise and cloud account takeover.',
    remediationSteps: [
      '1. Remove hardcoded API tokens from source code and configuration files.',
      '2. Rotate all exposed Quantum Provider API keys immediately in the provider portal.',
      '3. Store secrets securely in AWS Secrets Manager or HashiCorp Vault.',
      '4. Enforce pre-commit git hooks to scan for credential and token patterns.',
      '5. Restrict QPU API key permissions to specific VPC IP ranges.',
    ],
  },

  'quantum-missing-api-authorization': {
    id: 'quantum-missing-api-authorization',
    alias: 'quantum_missing_api_authorization',
    stageId: 2,
    project: 'QuantumOps',
    title: 'Missing API Authorization',
    category: 'API Security',
    domain: 'API Security',
    cvss: '8.7',
    cve: 'CVE-2026-8842',
    severity: 'HIGH',
    status: 'unresolved',
    description:
      'QuantumOps circuit submission and job dispatch endpoints (/api/v1/jobs/submit) lack proper role-based authorization guards, permitting authenticated standard users to trigger unrestricted quantum execution on production backends.',
    attackScenario:
      'A standard tenant user with read-only permissions sends a POST request directly to /api/v1/jobs/submit, queueing arbitrary quantum simulation workloads without the required "quantum:execute" permission scope.',
    businessImpact:
      'Resource starvation of critical quantum jobs, unauthorized execution of resource-intensive simulations, and violation of multi-tenant isolation boundaries.',
    originalCode: `@router.post("/api/v1/jobs/submit")
async def submit_quantum_job(job_spec: JobSpec, user: User = Depends(get_current_user)):
    job_id = await quantum_scheduler.enqueue(job_spec)
    return {"status": "queued", "job_id": job_id}`,
    patchedCode: `from auth import require_permission, PermissionScope

@router.post("/api/v1/jobs/submit")
async def submit_quantum_job(
    job_spec: JobSpec,
    user: User = Depends(get_current_user)
):
    await require_permission(user, PermissionScope.QUANTUM_EXECUTE, tenant_id=job_spec.tenant_id)
    job_id = await quantum_scheduler.enqueue(job_spec, submitted_by=user.id)
    return {"status": "queued", "job_id": job_id}`,
    remediation: `// SECURED: Enforce Role-Based Permission Validation\nawait require_permission(user, PermissionScope.QUANTUM_EXECUTE, tenant_id=job_spec.tenant_id)`,
    diff_file: 'routes/job_dispatch.py',
    diff_before: `@router.post("/api/v1/jobs/submit")\nasync def submit_quantum_job(job_spec: JobSpec, user: User = Depends(get_current_user)):\n    job_id = await quantum_scheduler.enqueue(job_spec)`,
    diff_after: `@router.post("/api/v1/jobs/submit")\nasync def submit_quantum_job(job_spec: JobSpec, user: User = Depends(get_current_user)):\n    await require_permission(user, PermissionScope.QUANTUM_EXECUTE, tenant_id=job_spec.tenant_id)\n    job_id = await quantum_scheduler.enqueue(job_spec, submitted_by=user.id)`,
    diff_reason: 'Enforces granular role-based authorization and tenant verification before enqueueing jobs.',
    expectedChanges:
      'Implement strict permission checks (QUANTUM_EXECUTE) and tenant validation on all job submission APIs.',
    whyThisMatters:
      'Authentication alone is insufficient; endpoints must verify granular permissions to prevent privilege abuse.',
    remediationSteps: [
      '1. Add authorization middleware with granular permission scopes to all dispatch routes.',
      '2. Verify user tenant membership against target resource tenant identifiers.',
      '3. Implement rate-limiting per tenant on compute-heavy quantum job APIs.',
      '4. Return HTTP 403 Forbidden with security audit logging for unauthorized attempts.',
      '5. Automate role-permission unit tests in the continuous integration pipeline.',
    ],
  },

  'quantum-excessive-privilege-assignment': {
    id: 'quantum-excessive-privilege-assignment',
    alias: 'quantum_excessive_privilege_assignment',
    stageId: 3,
    project: 'QuantumOps',
    title: 'Excessive Privilege Assignment',
    category: 'Access Control',
    domain: 'Access Control',
    cvss: '8.1',
    cve: 'CVE-2026-7734',
    severity: 'HIGH',
    status: 'unresolved',
    description:
      'QuantumOps worker service accounts and IAM execution roles are assigned wildcard (*:*) administrative privileges across all quantum backend clusters and cloud storage buckets instead of least-privilege scoping.',
    attackScenario:
      'An attacker exploiting a minor vulnerability in a worker container uses the associated service account token to access global administrative APIs, modify cluster configurations, and exfiltrate all tenant datasets.',
    businessImpact:
      'Lateral privilege escalation across the entire cloud infrastructure, unauthorized infrastructure changes, and compromise of all hosted tenant workloads.',
    originalCode: `{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "quantum:*",
      "Resource": "*"
    }
  ]
}`,
    patchedCode: `{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "quantum:GetJobStatus",
        "quantum:ReadResult",
        "quantum:CancelJob"
      ],
      "Resource": "arn:aws:quantum:us-east-1:123456789012:job/\${aws:PrincipalTag/TenantId}/*"
    }
  ]
}`,
    remediation: `// SECURED: Least-Privilege IAM Policy with Resource Constraints\n"Action": ["quantum:GetJobStatus", "quantum:ReadResult", "quantum:CancelJob"],\n"Resource": "arn:aws:quantum:us-east-1:123456789012:job/\${aws:PrincipalTag/TenantId}/*"`,
    diff_file: 'policies/worker_role_policy.json',
    diff_before: `"Action": "quantum:*",\n"Resource": "*"`,
    diff_after: `"Action": ["quantum:GetJobStatus", "quantum:ReadResult", "quantum:CancelJob"],\n"Resource": "arn:aws:quantum:us-east-1:123456789012:job/\${aws:PrincipalTag/TenantId}/*"`,
    diff_reason: 'Replaces wildcard administrative permissions with restricted action sets and tenant-bounded resource ARNs.',
    expectedChanges:
      'Replace wildcard IAM roles with least-privilege policies restricted to specific actions and tenant-tagged resources.',
    whyThisMatters:
      'Excessive privileges significantly expand the blast radius when individual worker nodes or service tokens are compromised.',
    remediationSteps: [
      '1. Audit and revoke all wildcard IAM policies across worker nodes and microservices.',
      '2. Scope permissions to exact API actions (GetJobStatus, ReadResult, CancelJob).',
      '3. Restrict resource ARNs to specific tenant namespaces and cluster environments.',
      '4. Enable AWS IAM Access Analyzer to detect overly permissive policy grants.',
      '5. Implement automated temporary credential expiration with maximum 1-hour validity.',
    ],
  },

  'quantum-insecure-data-serialization': {
    id: 'quantum-insecure-data-serialization',
    alias: 'quantum_insecure_data_serialization',
    stageId: 4,
    project: 'QuantumOps',
    title: 'Insecure Data Serialization',
    category: 'Data Security',
    domain: 'Data Security',
    cvss: '6.8',
    cve: 'CVE-2026-6412',
    severity: 'MEDIUM',
    status: 'unresolved',
    description:
      'Quantum circuit intermediate representations and calibration matrices are serialized using Python pickle without cryptographic signing or safe deserialization checks, enabling arbitrary code execution upon loading state payloads.',
    attackScenario:
      'An adversary submits a malicious circuit state file containing an embedded pickle payload to the circuit optimizer, triggering arbitrary command execution in the worker execution pod when unpickling.',
    businessImpact:
      'Remote code execution within the quantum simulation environment, container escape risks, and potential tampering with quantum algorithm results.',
    originalCode: `def load_circuit_state(raw_data: bytes) -> CircuitGraph:
    circuit_data = pickle.loads(raw_data)
    return CircuitGraph.from_dict(circuit_data)`,
    patchedCode: `import json
from pydantic import BaseModel, ValidationError

class SafeCircuitSchema(BaseModel):
    qubits: int
    gates: list[dict]
    parameters: dict[str, float]

def load_circuit_state(raw_data: bytes) -> CircuitGraph:
    data_dict = json.loads(raw_data.decode('utf-8'))
    validated_schema = SafeCircuitSchema.model_validate(data_dict)
    return CircuitGraph.from_dict(validated_schema.model_dump())`,
    remediation: `// SECURED: JSON Schema Validation over Safe Serialization\ndata_dict = json.loads(raw_data.decode('utf-8'))\nvalidated_schema = SafeCircuitSchema.model_validate(data_dict)`,
    diff_file: 'circuits/serializer.py',
    diff_before: `def load_circuit_state(raw_data: bytes) -> CircuitGraph:\n    circuit_data = pickle.loads(raw_data)\n    return CircuitGraph.from_dict(circuit_data)`,
    diff_after: `def load_circuit_state(raw_data: bytes) -> CircuitGraph:\n    data_dict = json.loads(raw_data.decode('utf-8'))\n    validated_schema = SafeCircuitSchema.model_validate(data_dict)\n    return CircuitGraph.from_dict(validated_schema.model_dump())`,
    diff_reason: 'Replaces insecure pickle deserialization with structured JSON parsing and Pydantic schema validation.',
    expectedChanges:
      'Migrate all circuit state persistence from binary pickle to strict typed JSON/Protobuf formats with Pydantic validation.',
    whyThisMatters:
      'Pickle deserialization of untrusted payloads is inherently insecure and directly allows arbitrary code execution.',
    remediationSteps: [
      '1. Deprecate pickle and marshal serialization for all external and stored data.',
      '2. Implement strict typed JSON or Protocol Buffer schemas for circuit representations.',
      '3. Validate all incoming circuit definitions with Pydantic models before processing.',
      '4. Sanitize parameters and gate definitions against schema whitelists.',
      '5. Add automated unit tests with adversarial serialized payloads to verify rejection.',
    ],
  },

  'quantum-missing-request-validation': {
    id: 'quantum-missing-request-validation',
    alias: 'quantum_missing_request_validation',
    stageId: 5,
    project: 'QuantumOps',
    title: 'Missing Request Validation',
    category: 'Application Security',
    domain: 'Application Security',
    cvss: '6.1',
    cve: 'CVE-2026-5590',
    severity: 'MEDIUM',
    status: 'unresolved',
    description:
      'QuantumOps circuit compilation parameters accept unbounded qubit counts, excessive gate depths, and negative timeout values without input boundary validation, leading to QPU resource exhaustion and buffer overflows.',
    attackScenario:
      'An attacker submits a compilation request with qubit_count=1000000 and gate_depth=999999999, causing memory exhaustion and crash loops in the quantum transpiler service.',
    businessImpact:
      'Denial of service for compilation pipelines, degraded performance for all active users, and potential crash of cluster node orchestrators.',
    originalCode: `@router.post("/api/v1/circuits/compile")
async def compile_circuit(request: Request):
    payload = await request.json()
    compiled = transpile(payload.get("circuit"), qubits=payload.get("qubit_count"))
    return {"compiled_circuit": compiled}`,
    patchedCode: `from pydantic import BaseModel, Field

class CompileRequest(BaseModel):
    circuit: str = Field(..., max_length=50000)
    qubit_count: int = Field(..., ge=1, le=127)
    optimization_level: int = Field(default=1, ge=0, le=3)
    timeout_sec: int = Field(default=30, ge=1, le=300)

@router.post("/api/v1/circuits/compile")
async def compile_circuit(req: CompileRequest):
    compiled = transpile(req.circuit, qubits=req.qubit_count, opt_level=req.optimization_level)
    return {"compiled_circuit": compiled}`,
    remediation: `// SECURED: Pydantic Input Boundary & Type Validation\nclass CompileRequest(BaseModel):\n    qubit_count: int = Field(..., ge=1, le=127)\n    circuit: str = Field(..., max_length=50000)`,
    diff_file: 'routes/transpiler.py',
    diff_before: `@router.post("/api/v1/circuits/compile")\nasync def compile_circuit(request: Request):\n    payload = await request.json()\n    compiled = transpile(payload.get("circuit"), qubits=payload.get("qubit_count"))`,
    diff_after: `@router.post("/api/v1/circuits/compile")\nasync def compile_circuit(req: CompileRequest):\n    compiled = transpile(req.circuit, qubits=req.qubit_count, opt_level=req.optimization_level)`,
    diff_reason: 'Enforces strict Pydantic parameter boundaries for qubit counts, payload size, and compiler timeout limits.',
    expectedChanges:
      'Implement strict schema validation with min/max boundary constraints on all compilation parameters.',
    whyThisMatters:
      'Unvalidated request parameters allow malicious or malformed inputs to trigger server crashes and resource exhaustion.',
    remediationSteps: [
      '1. Implement Pydantic schema validation models for all API route handlers.',
      '2. Enforce upper limits on qubit count (max 127) and circuit string length (max 50KB).',
      '3. Restrict compiler optimization levels and execution timeouts to bounded ranges.',
      '4. Reject malformed payloads immediately with HTTP 422 Unprocessable Entity.',
      '5. Add automated fuzz testing for API input boundary verification.',
    ],
  },

  'quantum-insufficient-audit-logging': {
    id: 'quantum-insufficient-audit-logging',
    alias: 'quantum_insufficient_audit_logging',
    stageId: 6,
    project: 'QuantumOps',
    title: 'Insufficient Audit Logging',
    category: 'Monitoring & Logging',
    domain: 'Monitoring & Logging',
    cvss: '3.8',
    cve: 'CVE-2026-3195',
    severity: 'LOW',
    status: 'unresolved',
    description:
      'QuantumOps execution lifecycle events, job cancellation requests, and hardware backend configuration changes are not logged to centralized telemetry, preventing detection of unauthorized modifications and anomalous usage patterns.',
    attackScenario:
      'An unauthorized operator cancels competing research jobs and modifies simulation parameters, leaving no audit log trail for forensic investigation.',
    businessImpact:
      'Inability to trace security incidents, failure to satisfy compliance audit requirements (SOC 2, ISO 27001), and delayed detection of malicious insider activity.',
    originalCode: `async def cancel_job(job_id: str, user_id: str):
    job = await job_store.get(job_id)
    await job.abort()
    return {"status": "cancelled"}`,
    patchedCode: `from quantum_telemetry import log_audit_event, AuditSeverity

async def cancel_job(job_id: str, user_id: str, client_ip: str):
    job = await job_store.get(job_id)
    await job.abort()
    await log_audit_event(
        event_type="JOB_CANCELLED",
        severity=AuditSeverity.INFO,
        details={"job_id": job_id, "user_id": user_id, "ip": client_ip, "timestamp": utc_now()}
    )
    return {"status": "cancelled"}`,
    remediation: `// SECURED: Centralized Security Audit Event Telemetry\nawait log_audit_event(event_type="JOB_CANCELLED", details={"job_id": job_id, "user_id": user_id, "ip": client_ip})`,
    diff_file: 'services/job_manager.py',
    diff_before: `async def cancel_job(job_id: str, user_id: str):\n    job = await job_store.get(job_id)\n    await job.abort()`,
    diff_after: `async def cancel_job(job_id: str, user_id: str, client_ip: str):\n    job = await job_store.get(job_id)\n    await job.abort()\n    await log_audit_event("JOB_CANCELLED", details={"job_id": job_id, "user_id": user_id, "ip": client_ip})`,
    diff_reason: 'Emits structured audit logging for job lifecycle state changes to centralized security SIEM.',
    expectedChanges:
      'Implement centralized structured security audit logging for all job lifecycle transitions and administrative actions.',
    whyThisMatters:
      'Comprehensive audit logging is required for security incident response, forensic investigations, and compliance certification.',
    remediationSteps: [
      '1. Integrate centralized security audit logging into all job management operations.',
      '2. Include timestamp, user ID, client IP, action type, and resource ID in all log events.',
      '3. Stream audit logs to a secure, tamper-resistant SIEM (e.g., Datadog, Splunk, CloudWatch).',
      '4. Set up real-time alerting for suspicious bursts of job cancellations or failures.',
      '5. Retain audit logs for at least 90 days in accordance with organizational compliance policies.',
    ],
  },
};

export const QUANTUM_OPS_FINDINGS = Object.values(QUANTUM_OPS_THREATS);
