import { validateCorrelationPreview } from './correlation-validation';
const input = { policy_id: '00000000-0000-4000-8000-000000000001', policy_version: 1,
  rules: ['00000000-0000-4000-8000-000000000002'], window_minutes: 15, minimum_findings: 2,
  from: '2026-11-26T12:00:00Z', until: '2026-11-26T13:00:00Z' };
describe('correlation preview validation', () => {
  test('accepts bounded UTC aligned windows', () => expect(() => validateCorrelationPreview(input)).not.toThrow());
  test('rejects incomplete windows and duplicate rules', () => {
    expect(() => validateCorrelationPreview({ ...input, from: '2026-11-26T12:01:00Z' })).toThrow();
    expect(() => validateCorrelationPreview({ ...input, rules: [...input.rules, ...input.rules] })).toThrow();
  });
  test('rejects fractional policy controls and excessive ranges', () => {
    expect(() => validateCorrelationPreview({ ...input, minimum_findings: 2.5 })).toThrow();
    expect(() => validateCorrelationPreview({ ...input, until: '2026-12-10T13:00:00Z' })).toThrow();
  });
});
