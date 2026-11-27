import { collectHistoricalOutcomes, appendHistoricalFacts, recheckHistoricalSources } from './historical-outcomes';
import { parsePlan } from './agentic';
const rule = '00000000-0000-4000-8000-000000000001';
const id = '00000000-0000-4000-8000-000000000002';
const restricted = '00000000-0000-4000-8000-000000000003';
const row = { id, revision: 2, status: 'closed', tlp: 'TLP:CLEAR', severity: 'low', priority: 'medium', finding_count: 1,
  closure: { classification: 'false_positive' } };
const ref = { index: 'PRIVATE_INDEX', document_id: 'PRIVATE_DOC' };
const page = { revision: 2, findings: [ref], unavailable_count: 0, observations: [{ ...ref, wazuh_rule_uuid: rule, techniques: [], tactics: [], entities: [] }] };
describe('historical outcomes disclosure boundary', () => {
  test('restricted cases are never read or included and UUID never enters digest', async () => {
    const reader = { list: async () => ({ incidents: [row, { ...row, id: restricted, tlp: 'TLP:RED' }] }),
      detail: jest.fn().mockResolvedValue({ incident: row }), findings: jest.fn().mockResolvedValue(page) };
    const report = await collectHistoricalOutcomes(reader, 'current', rule, 1, ['TLP:CLEAR', 'TLP:RED'], () => {});
    expect(report.matched).toBe(1); expect(report.falsePositive).toBe(1);
    expect(reader.detail).toHaveBeenCalledTimes(1);
    const digest = { facts: [], scope: 'first_finding_page' as const, complete_link_coverage: true };
    appendHistoricalFacts(digest, report);
    expect(JSON.stringify(digest)).not.toContain(rule);
    expect(JSON.stringify(digest)).not.toContain(restricted);
    expect(JSON.stringify(digest)).not.toContain('PRIVATE');
    reader.detail.mockResolvedValue({ incident: { ...row, revision: 3 } });
    await expect(recheckHistoricalSources(reader, report, ['TLP:CLEAR'], () => {})).rejects.toThrow();
  });
  test('probe is disabled by default and exact UUID is required', () => {
    const raw = '{"probes":[{"kind":"rule_history","sample":1}]}';
    expect(() => parsePlan(raw, page, false)).toThrow();
    expect(parsePlan(raw, page, false, true)).toEqual([{ kind: 'rule_history', sample: 1 }]);
    expect(() => parsePlan(raw, { observations: [{ rule_id: rule }] }, false, true)).toThrow();
  });
});
