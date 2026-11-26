import type { CorrelationPolicyDefinition } from './contracts';
import { validateCorrelationPolicy } from './correlation-validation';

/** Same length-prefixed UTF-8 fields as indexer AnalyticsWindow.policyFingerprint. */
export function analyticsPolicyBytes(policy: CorrelationPolicyDefinition): Uint8Array {
  validateCorrelationPolicy(policy);
  const encoder = new TextEncoder();
  const parts = ['wazuh-analytics-policy-v1', policy.policy_id, String(policy.policy_version),
    String(policy.window_minutes), String(policy.minimum_findings), ...[...policy.rules].sort()].map(part => encoder.encode(part));
  const bytes = new Uint8Array(parts.reduce((n, part) => n + 4 + part.byteLength, 0));
  const view = new DataView(bytes.buffer);
  let offset = 0;
  for (const part of parts) {
    view.setUint32(offset, part.byteLength, false); offset += 4;
    bytes.set(part, offset); offset += part.byteLength;
  }
  return bytes;
}

export async function analyticsPolicyFingerprint(policy: CorrelationPolicyDefinition, subtle: SubtleCrypto): Promise<string> {
  const bytes = analyticsPolicyBytes(policy);
  const digest = await subtle.digest('SHA-256', bytes.buffer as ArrayBuffer);
  return Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, '0')).join('');
}
