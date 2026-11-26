import { buildDigest, checkedSummary, parseRecommendations } from './evidence';
const id = '00000000-0000-4000-8000-000000000001';
const summary = { id, revision: 3, tlp: 'TLP:AMBER', status: 'active', severity: 'high', priority: 'urgent',
  owner: 'PRIVATE_USER', title: 'PRIVATE_TITLE', description: 'PRIVATE_DESCRIPTION', finding_count: 1 };
const ref = { index: 'PRIVATE_INDEX', document_id: 'PRIVATE_ID' };
const page = { revision: 3, findings: [ref], unavailable_count: 0, observations: [{ ...ref,
  timestamp: '2026-11-26T12:00:00Z', rule_title: 'PRIVATE_RULE', techniques: ['T1059', 'PRIVATE_TEXT'],
  tactics: ['TA0002'], entities: [{ kind: 'host', value: 'PRIVATE_HOST' }] }] };
describe('incident assessment evidence boundary', () => {
  test('projects only fixed facts and catalog identifiers', () => {
    const digest = buildDigest(checkedSummary({ incident: summary }, id, 3, ['TLP:AMBER']), page);
    expect(JSON.stringify(digest)).not.toContain('PRIVATE');
    expect(JSON.stringify(digest)).not.toContain('2026-11');
    expect(digest.complete_link_coverage).toBe(true);
    expect(digest.facts.some(fact => Array.isArray(fact.value) && fact.value.includes('T1059'))).toBe(true);
  });
  test('rejects disclosure labels and revisions outside policy', () => {
    expect(() => checkedSummary({ incident: summary }, id, 3, ['TLP:CLEAR'])).toThrow();
    expect(() => checkedSummary({ incident: { ...summary, tlp: 'TLP:RED' } }, id, 3, ['TLP:RED'])).toThrow();
    expect(() => checkedSummary({ incident: summary }, id, 4, ['TLP:AMBER'])).toThrow();
    expect(() => buildDigest(summary, { ...page, unavailable_count: 1 })).toThrow();
  });
  test('rejects invented evidence references, unknown actions and free-text output', () => {
    const digest = buildDigest(summary, page);
    expect(parseRecommendations('{"recommendations":[{"action":"review_detection","evidence_refs":["F1"]}]}', digest)).toHaveLength(1);
    for (const raw of ['{"recommendations":[{"action":"review_detection","evidence_refs":["F999"]}]}',
      '{"recommendations":[{"action":"execute","evidence_refs":["F1"]}]}',
      '{"recommendations":[{"action":"review_detection","evidence_refs":["F1"],"text":"unexpected"}]}']) {
      expect(() => parseRecommendations(raw, digest)).toThrow();
    }
  });
});
