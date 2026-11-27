import { summarizeFindings } from './finding-intelligence-model';
import type { FindingObservation } from '../../../../common/incidents/contracts';
const base: FindingObservation = { index: 'index', document_id: 'a', timestamp: '2026-11-26T12:00:00Z', rule_id: '1',
  rule_title: 'Detection', entities: [{ kind: 'host', value: 'host1', field: 'host.name' }, { kind: 'host', value: 'host1', field: 'host.hostname' }],
  techniques: ['T1059'], tactics: ['TA0002'] };
describe('finding intelligence', () => {
  test('counts distinct findings per entity rather than repeated source fields', () => {
    const result = summarizeFindings([base, { ...base, document_id: 'b' }]);
    expect(result.entities).toEqual([{ kind: 'host', value: 'host1', count: 2, fields: ['host.name', 'host.hostname'] }]);
    expect(result.techniques).toEqual(['T1059']);
  });
  test('orders known timestamps and leaves missing timestamps last', () => {
    const result = summarizeFindings([{ ...base, document_id: 'unknown', timestamp: null }, base,
      { ...base, document_id: 'earlier', timestamp: '2026-11-26T11:00:00Z' }]);
    expect(result.ordered.map(item => item.document_id)).toEqual(['earlier', 'a', 'unknown']);
  });
});
