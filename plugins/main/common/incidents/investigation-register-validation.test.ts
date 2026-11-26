import type { CollaborationPage, EvidenceArtifact, IncidentRelation } from './contracts';
import { validateInvestigationRegister, validateTags } from './investigation-register-validation';

const id = '00000000-0000-4000-8000-000000000001';
const target = '00000000-0000-4000-8000-000000000002';
const at = '2026-11-26T12:00:00Z';
const relation: IncidentRelation = { id: id + ':3', target_id: target, type: 'possible_duplicate', reason: 'Hypothesis', recorded_by: 'alice', recorded_at: at };
const artifact: EvidenceArtifact = { id: id + ':4', type: 'log_export', label: 'Export', sha256: 'a'.repeat(64),
  custody_reference: 'vault-123', recorded_by: 'alice', recorded_at: at, origin: 'analyst_attested_external_artifact',
  state: 'recorded', withdrawn_by: null, withdrawn_at: null, withdrawal_reason: null };
const page: CollaborationPage = { notes: [], tasks: [], observed_revision: 5, activity_pending: false, incident_relations: [relation], evidence_register: [artifact] };

describe('investigation register projection', () => {
  test('canonical tags and limits', () => {
    expect(validateTags(['soc', 'phishing'])).toEqual(['phishing', 'soc']);
    for (const input of [null, ['bad space'], ['a', 'a'], ['UPPER'], Array.from({ length: 26 }, (_, n) => 'tag' + n), ['a'.repeat(65)]]) {
      expect(() => validateTags(input)).toThrow();
    }
  });
  test('accepts complete records and older indexers without either field', () => {
    expect(() => validateInvestigationRegister(page, id)).not.toThrow();
    expect(() => validateInvestigationRegister({ notes: [], tasks: [], observed_revision: 1, activity_pending: false }, id)).not.toThrow();
    expect(() => validateInvestigationRegister({ ...page, evidence_register: undefined }, id)).toThrow();
  });
  test('rejects self links, duplicate targets and cross-record identity collisions', () => {
    expect(() => validateInvestigationRegister({ ...page, incident_relations: [{ ...relation, target_id: id }] }, id)).toThrow();
    expect(() => validateInvestigationRegister({ ...page, incident_relations: [relation, { ...relation, id: id + ':5' }] }, id)).toThrow();
    expect(() => validateInvestigationRegister({ ...page, evidence_register: [{ ...artifact, id: id + ':3' }] }, id)).toThrow();
  });
  test('rejects forged fields, invalid digest and stale or noncanonical identity', () => {
    for (const row of [
      { ...artifact, raw: 'restricted' }, { ...artifact, sha256: 'A'.repeat(64) },
      { ...artifact, id: id + ':6' }, { ...artifact, id: id + ':04' },
      { ...artifact, label: 'bad\nlabel' },
    ]) expect(() => validateInvestigationRegister({ ...page, evidence_register: [row] }, id)).toThrow();
  });
  test('withdrawal requires attribution and cannot predate registration', () => {
    const withdrawn: EvidenceArtifact = { ...artifact, state: 'withdrawn', withdrawn_by: 'bob', withdrawn_at: '2026-11-26T12:01:00Z', withdrawal_reason: 'Wrong file' };
    expect(() => validateInvestigationRegister({ ...page, evidence_register: [withdrawn] }, id)).not.toThrow();
    expect(() => validateInvestigationRegister({ ...page, evidence_register: [{ ...artifact, state: 'withdrawn' }] }, id)).toThrow();
    expect(() => validateInvestigationRegister({ ...page, evidence_register: [{ ...withdrawn, withdrawn_at: '2026-11-26T11:59:00Z' }] }, id)).toThrow();
    expect(() => validateInvestigationRegister({ ...page, evidence_register: [artifact, { ...artifact, id: id + ':5' }] }, id)).toThrow();
  });
});
