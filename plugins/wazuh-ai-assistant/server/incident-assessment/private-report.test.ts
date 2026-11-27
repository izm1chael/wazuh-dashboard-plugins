import { buildPrivateReport, canonicalReport } from './private-report';
import { createHash } from 'crypto';
const digest = { scope: 'first_finding_page' as const, complete_link_coverage: false,
  facts: [{ ref: 'F1', kind: 'status', value: 'active' }] };
const input = { incident_id: '00000000-0000-4000-8000-000000000001', observed_revision: 3,
  mode: 'ai_review' as const, advisory_only: true as const, digest, probes: [],
  recommendations: [{ action: 'review_detection' as const, evidence_refs: ['F1'] }] };
describe('private assessment copy', () => {
  test('records model, revision, time and digest hash without marking chat replay safe', () => {
    const report = buildPrivateReport(input, 'approved-provider', 'local-model', new Date('2026-11-26T12:00:00Z'));
    expect(report.provenance.digest_sha256).toBe(createHash('sha256').update(JSON.stringify(digest)).digest('hex'));
    const { report_sha256, report_hash_serialization, ...core } = report.provenance;
    expect(report_hash_serialization).toBe('sorted-json-v1');
    expect(report_sha256).toBe(createHash('sha256').update(canonicalReport({ provenance: core, assessment: input })).digest('hex'));
    expect(report_sha256).not.toBe(createHash('sha256').update(canonicalReport({ provenance: core, assessment: { ...input, observed_revision: 4 } })).digest('hex'));
    expect(canonicalReport({ b: 2, a: 1 })).toBe(canonicalReport({ a: 1, b: 2 }));
    expect(report.document.title).toContain('r3');
    expect(report.document.messages[0].privacyEnabled).toBe(false);
    expect(report.document.messages[0].content).toContain('Private editable');
    expect(report.document.messages[0].content).toContain(report.provenance.assessment_id);
  });
});
