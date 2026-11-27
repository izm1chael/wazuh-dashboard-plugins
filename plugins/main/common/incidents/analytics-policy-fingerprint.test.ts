import { createHash } from 'crypto';
import { analyticsPolicyBytes } from './analytics-policy-fingerprint';

const policy = { policy_id: '00000000-0000-4000-8000-000000000002', policy_version: 1,
  window_minutes: 15, minimum_findings: 2, rules: ['00000000-0000-4000-8000-000000000003'] };
const digest = (definition: typeof policy) => createHash('sha256').update(analyticsPolicyBytes(definition)).digest('hex');

describe('analytics policy approval fingerprint', () => {
  it('matches indexer length-prefixed reference vector', () => {
    expect(digest(policy)).toBe('954f740e1b4222a972f26ae88dda15cddad8480f763de73f1fb180dee1185778');
    expect(digest({ ...policy, minimum_findings: 3 })).not.toBe(digest(policy));
    expect(digest({ ...policy, policy_version: 2 })).not.toBe(digest(policy));
    expect(digest({ ...policy, window_minutes: 20 })).not.toBe(digest(policy));
  });
  it('canonicalizes rule order and rejects duplicates', () => {
    const rules = [...policy.rules, '00000000-0000-4000-8000-000000000004'];
    expect(digest({ ...policy, rules })).toBe(digest({ ...policy, rules: [...rules].reverse() }));
    expect(() => digest({ ...policy, rules: [...policy.rules, ...policy.rules] })).toThrow();
  });
});
