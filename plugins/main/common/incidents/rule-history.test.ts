import { summarizeRuleHistory } from './rule-history';
import type { IncidentSummary, FindingPage } from './contracts';
const rule = '00000000-0000-4000-8000-000000000001';
const other = '00000000-0000-4000-8000-000000000002';
function sample(id: string, ids: Array<string | null>, total: number, unavailable = 0) {
  const summary = { id, revision: 3, status: 'closed', finding_count: total, closure: { classification: 'false_positive' } } as IncidentSummary;
  const findings = ids.map((_, n) => ({ index: 'index', document_id: String(n) }));
  const page = { revision: 3, findings, unavailable_count: unavailable,
    ...(total > 5 ? { next_offset: 5 } : {}), observations: ids.map((value, n) => ({ ...findings[n], wazuh_rule_uuid: value })) } as FindingPage;
  return { summary, page };
}
describe('bounded rule outcome sample', () => {
  test('counts each matching incident once, never findings as labels', () => {
    const report = summarizeRuleHistory(rule, 2, [sample('one', [rule, rule], 2), sample('two', [other], 1), sample('three', [null], 1)], true);
    expect(report.matched_incidents).toBe(1);
    expect(report.classifications.false_positive).toBe(1);
    expect(report.complete_nonmatches).toBe(1);
    expect(report.uncertain_nonmatches).toBe(1);
  });
  test('unavailable and uninspected links cannot be complete nonmatches', () => {
    const report = summarizeRuleHistory(rule, 2, [sample('one', [rule], 6, 4), sample('two', [], 1, 1)], false);
    expect(report.matched_with_partial_coverage).toBe(1);
    expect(report.uncertain_nonmatches).toBe(1);
    expect(report.uninspected_links).toBe(1);
  });
  test('rejects missing page positions, duplicate incidents and stale pages', () => {
    expect(() => summarizeRuleHistory(rule, 2, [sample('one', [rule], 2)], false)).toThrow();
    const row = sample('one', [rule], 1);
    expect(() => summarizeRuleHistory(rule, 2, [row, row], false)).toThrow();
    expect(() => summarizeRuleHistory(rule, 2, [{ ...row, page: { ...row.page, revision: 4 } }], false)).toThrow();
  });
});
