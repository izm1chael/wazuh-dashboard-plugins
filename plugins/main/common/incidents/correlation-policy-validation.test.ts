import { validateCorrelationPolicy } from './correlation-validation';
const policy = { policy_id: '00000000-0000-4000-8000-000000000001', policy_version: 1,
  rules: ['00000000-0000-4000-8000-000000000002'], window_minutes: 15, minimum_findings: 2 };
describe('saved correlation policy validation', () => {
  test('validates definitions without requiring a time range', () => expect(() => validateCorrelationPolicy(policy)).not.toThrow());
  test('rejects empty rules and fractional versions', () => {
    expect(() => validateCorrelationPolicy({ ...policy, rules: [] })).toThrow();
    expect(() => validateCorrelationPolicy({ ...policy, policy_version: 1.5 })).toThrow();
  });
});
