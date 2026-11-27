import { Indicator, IndicatorInput, IndicatorSighting, validateBatch, validateCatalog, validateIndicator, validateMutation } from './indicator-contract';
import { exportStix, importStix } from './stix-indicator-exchange';

const A = '2026-11-25T00:00:00Z', B = '2026-11-26T00:00:00Z', C = '2026-11-27T00:00:00Z';
const ID = '00000000-0000-4000-8000-000000000001', ID2 = '00000000-0000-4000-8000-000000000002';
const BUNDLE = '00000000-0000-4000-8000-000000000003';
const input: IndicatorInput = { type: 'ipv4', value: '192.0.2.1', source: 'Feed', external_id: null,
  confidence: 70, tlp: 'TLP:CLEAR', valid_from: A, valid_until: C };
const row: Indicator = { ...input, id: ID, created_by: 'alice', created_at: B, created_revision: 1,
  revoked_by: null, revoked_at: null, revoked_revision: null, revocation_reason: null, state: 'active', sightings: [] };
const sight: IndicatorSighting = { revision: 2, observed_at: A, source: 'External report', count: 3,
  recorded_by: 'alice', recorded_at: B, origin: 'analyst_attested_external_sighting',
  withdrawn_by: null, withdrawn_at: null, withdrawn_revision: null, withdrawal_reason: null };
const catalog = (revision: number, indicators: Indicator[], observed_at = B) => ({ revision, indicators, observed_at });

describe('CTI catalog', () => {
  it('canonicalizes supported values and rejects ambiguous identities', () => {
    expect(validateIndicator({ ...input, type: 'domain', value: 'EXAMPLE.ORG' }).value).toBe('example.org');
    expect(validateIndicator({ ...input, type: 'sha256', value: 'A'.repeat(64) }).value).toBe('a'.repeat(64));
    for (const patch of [{ value: '192.0.2.01' }, { value: '192.0.2.0/24' }, { value: '::1' },
      { type: 'domain', value: '*.example.org' }, { type: 'domain', value: 'K.example.org' },
      { confidence: 101 }, { confidence: 1.1 }, { valid_until: A }, { valid_from: '2026-02-30T00:00:00Z' },
      { valid_from: '2026-11-25T00:00:00.0001Z' }, { extra: 'forged' }]) {
      expect(() => validateIndicator({ ...input, ...patch } as IndicatorInput)).toThrow();
    }
    expect(() => validateBatch([input, input])).toThrow();
  });
  it('enforces complete catalog revisions and lifecycle state', () => {
    expect(validateCatalog(catalog(0, [])).revision).toBe(0);
    expect(validateCatalog(catalog(1, [row])).indicators).toHaveLength(1);
    expect(() => validateCatalog(catalog(1, [row], C))).toThrow();
    expect(() => validateCatalog(catalog(2, [row]))).toThrow();
    expect(() => validateCatalog(catalog(2, [row, { ...row, id: ID2, created_revision: 2 }]))).toThrow();
    const revoked: Indicator = { ...row, state: 'revoked', revoked_by: 'bob', revoked_at: B, revoked_revision: 2, revocation_reason: 'Superseded' };
    expect(validateCatalog(catalog(3, [revoked, { ...row, id: ID2, created_revision: 3 }])).indicators).toHaveLength(2);
    expect(() => validateMutation({ revision: 3, changed: 1 }, 1, 1)).toThrow();
  });
  it('retains externally attested sightings and withdrawal provenance', () => {
    expect(validateCatalog(catalog(2, [{ ...row, sightings: [sight] }])).indicators[0].sightings).toEqual([sight]);
    const withdrawn: IndicatorSighting = { ...sight, withdrawn_by: 'bob', withdrawn_at: B, withdrawn_revision: 3, withdrawal_reason: 'Wrong source' };
    expect(validateCatalog(catalog(3, [{ ...row, sightings: [withdrawn] }])).indicators[0].sightings[0].count).toBe(3);
    for (const patch of [{ revision: 1 }, { count: 0 }, { origin: 'verified' }, { observed_at: C },
      { withdrawn_by: 'bob' }, { raw: 'secret' }]) {
      expect(() => validateCatalog(catalog(2, [{ ...row, sightings: [{ ...sight, ...patch } as IndicatorSighting] }]))).toThrow();
    }
    expect(() => validateCatalog(catalog(2, [{ ...row, sightings: [sight] },
      { ...row, id: ID2, value: '192.0.2.2', created_revision: 2 }]))).toThrow();
  });
});

describe('strict STIX subset', () => {
  const bundle = exportStix([row], BUNDLE, B);
  const raw = JSON.stringify(bundle);
  it('round-trips all supported patterns without importing source metadata', () => {
    for (const [type, value] of [['ipv4', '192.0.2.1'], ['domain', 'example.org'], ['md5', 'a'.repeat(32)],
      ['sha1', 'b'.repeat(40)], ['sha256', 'c'.repeat(64)]] as const) {
      const exported = exportStix([{ ...row, type, value }], BUNDLE, B);
      const imported = importStix(JSON.stringify(exported), 'New source', 'TLP:AMBER')[0];
      expect(imported).toMatchObject({ type, value, source: 'New source', tlp: 'TLP:AMBER', external_id: 'indicator--' + ID });
    }
  });
  it('rejects marking-bearing and unsupported patterns and duplicate JSON keys', () => {
    for (const patch of [{ object_marking_refs: ['marking-definition--' + ID] }, { granular_markings: [] },
      { extensions: {} }, { revoked: true }, { pattern_type: 'sigma' }, { confidence: undefined }, { valid_until: undefined },
      { pattern: "[ipv4-addr:value = '192.0.2.1' OR ipv4-addr:value = '192.0.2.2']" }]) {
      expect(() => importStix(JSON.stringify({ ...bundle, objects: [{ ...bundle.objects[0], ...patch }] }), 'Feed', 'TLP:AMBER')).toThrow();
    }
    expect(() => importStix(raw.replace('"confidence":70', '"confidence":1,"confidence":70'), 'Feed', 'TLP:AMBER')).toThrow();
    expect(() => importStix(raw.replace('"confidence":70', '"\\u0063onfidence":1,"confidence":70'), 'Feed', 'TLP:AMBER')).toThrow();
  });
  it('blocks non-CLEAR, expired and revoked exports', () => {
    expect(() => exportStix([{ ...row, tlp: 'TLP:RED' }], BUNDLE, B)).toThrow();
    expect(() => exportStix([row], BUNDLE, C)).toThrow();
    expect(() => exportStix([{ ...row, state: 'revoked' }], BUNDLE, B)).toThrow();
  });
});
