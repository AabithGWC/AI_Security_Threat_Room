const API_BASE = window.location.origin.includes('5173') ? '' : window.location.origin;

export async function pingBackend() {
  const res = await fetch(`${API_BASE}/ping`);
  if (!res.ok) throw new Error('Backend ping failed');
  return res.json();
}

export async function sendChatMessage(message, sessionId = null) {
  const payload = { message };
  if (sessionId) payload.session_id = sessionId;

  const res = await fetch(`${API_BASE}/chat`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });

  if (!res.ok) {
    let errorDetail = `Server error ${res.status}`;
    try {
      const errJson = await res.json();
      if (errJson.detail) errorDetail = errJson.detail;
    } catch {}
    throw new Error(errorDetail);
  }

  return res.json();
}

export async function resetSession(sessionId) {
  const res = await fetch(`${API_BASE}/reset/${sessionId}`, { method: 'POST' });
  if (!res.ok) throw new Error('Failed to reset session');
  return res.json();
}

export async function fixThreatApi(threatId, payload = {}) {
  const res = await fetch(`${API_BASE}/security/fix/${threatId}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    let errorMsg = `Failed to fix threat ${threatId}`;
    try {
      const errJson = await res.json();
      if (errJson.message) errorMsg = errJson.message;
    } catch {}
    throw new Error(errorMsg);
  }
  return res.json();
}

export async function revokeThreatApi(threatId, payload = {}) {
  const res = await fetch(`${API_BASE}/security/revoke/${threatId}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    let errorMsg = `Failed to revoke fix for threat ${threatId}`;
    try {
      const errJson = await res.json();
      if (errJson.message) errorMsg = errJson.message;
    } catch {}
    throw new Error(errorMsg);
  }
  return res.json();
}

export async function resolveAllThreatsApi() {
  const res = await fetch(`${API_BASE}/security/resolve-all`, { method: 'POST' });
  if (!res.ok) throw new Error('Failed to resolve all threats');
  return res.json();
}

export async function revokeAllThreatsApi() {
  const res = await fetch(`${API_BASE}/security/revoke-all`, { method: 'POST' });
  if (!res.ok) throw new Error('Failed to revoke all threats');
  return res.json();
}

export function streamAuditApi(onData, onError, onComplete) {
  const eventSource = new EventSource(`${API_BASE}/security/audit/stream`);

  eventSource.onmessage = (event) => {
    try {
      if (!event.data) return;
      const data = JSON.parse(event.data);
      onData(data);
      if (data.type === 'done') {
        eventSource.close();
        if (onComplete) onComplete();
      }
    } catch (err) {
      console.error('Error parsing SSE event data:', err);
    }
  };

  eventSource.onerror = (err) => {
    eventSource.close();
    if (onError) {
      const msg = err && err.message ? err.message : 'Audit stream connection interrupted.';
      onError(new Error(msg));
    }
  };

  return () => {
    eventSource.close();
  };
}
