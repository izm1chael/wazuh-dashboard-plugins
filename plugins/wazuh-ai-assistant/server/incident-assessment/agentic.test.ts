import { buildDigest } from './evidence';
import { addPrevalence, exactRule, parsePlan, parseAgenticResult, prevalenceQuery } from './agentic';
const summary = { revision: 1, finding_count: 1, status: 'active', severity: 'high', priority: 'high', owner: null };
const ref = { index: 'private-index', document_id: 'private-doc' };
const page = { revision: 1, findings: [ref], unavailable_count: 0, observations: [{ ...ref, wazuh_rule_id: 'private-rule',
  rule_id: 'display-fallback', techniques: [], tactics: [], entities: [] }] };
describe('bounded agentic SOC', () => {
  test('only accepts an observed exact rule and available additional page', () => {
    expect(exactRule(page, 1)).toBe('private-rule');
    expect(parsePlan('{"probes":[{"kind":"rule_prevalence","sample":1}]}', page, false)).toHaveLength(1);
    expect(() => parsePlan('{"probes":[{"kind":"rule_prevalence","sample":2}]}', page, false)).toThrow();
    expect(() => parsePlan('{"probes":[{"kind":"more_linked_findings"}]}', page, false)).toThrow();
    expect(() => parsePlan('{"probes":[{"kind":"search","query":"*"}]}', page, true)).toThrow();
  });
  test('prevalence is bounded and no rule identifier reaches digest', () => {
    const digest = buildDigest(summary, page);
    const request = prevalenceQuery('private-rule', new Date('2026-11-26T12:00:00Z'));
    expect(request.body.size).toBe(0);
    expect(request.allow_partial_search_results).toBe(false);
    addPrevalence(digest, 1, { timed_out: false, _shards: { total: 1, failed: 0 }, hits: { total: { value: 10000, relation: 'gte' } } });
    expect(JSON.stringify(digest)).not.toContain('private-');
    expect(digest.facts.some(f => f.kind === 'rule_prevalence_is_lower_bound' && f.value === true)).toBe(true);
    expect(() => addPrevalence(digest, 1, { timed_out: true, _shards: { total: 1, failed: 0 }, hits: { total: { value: 0, relation: 'eq' } } })).toThrow();
  });
  test('classification and tuning remain cited hypotheses and proposals', () => {
    const digest = buildDigest(summary, page);
    const raw = JSON.stringify({ recommendations: [{ action: 'review_detection', evidence_refs: ['F1'] }],
      hypothesis: { action: 'insufficient_evidence', evidence_refs: ['F1'] },
      tuning: [{ action: 'compare_benign_baseline', evidence_refs: ['F1'] }] });
    expect(parseAgenticResult(raw, digest).tuning).toHaveLength(1);
    expect(() => parseAgenticResult(raw.replace('insufficient_evidence', 'confirmed_false_positive'), digest)).toThrow();
    expect(() => parseAgenticResult(raw.replace('compare_benign_baseline', 'disable_rule'), digest)).toThrow();
  });
});
