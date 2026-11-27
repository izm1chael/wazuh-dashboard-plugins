import React, { useState } from 'react';
import { EuiButton, EuiButtonEmpty, EuiCallOut, EuiFieldText, EuiFormRow, EuiPanel, EuiSelect, EuiSpacer, EuiText, EuiTitle } from '@elastic/eui';
import { EVIDENCE_TYPES, RELATION_TYPES } from '../../../../common/incidents/contracts';
import type { CollaborationPage, EvidenceArtifactType, IncidentRelationType, IncidentSummary, IndexerIncidentCommand } from '../../../../common/incidents/contracts';
import { LocalEvidenceVerifier } from './local-evidence-verifier';
import { validateTags } from '../../../../common/incidents/investigation-register-validation';

export function IncidentRegisterPanel({ page, incident, disabled, command, openRelated }: {
  page: CollaborationPage; incident: IncidentSummary; disabled: boolean; command: (value: IndexerIncidentCommand) => Promise<void>; openRelated?: (id: string) => void;
}) {
  const [tags, setTags] = useState((incident.tags ?? []).join(', '));
  const [target, setTarget] = useState('');
  const [relation, setRelation] = useState<IncidentRelationType>('related');
  const [relationReason, setRelationReason] = useState('');
  const [type, setType] = useState<EvidenceArtifactType>('log_export');
  const [label, setLabel] = useState('');
  const [digest, setDigest] = useState('');
  const [custody, setCustody] = useState('');
  const [reason, setReason] = useState('');
  const [selected, setSelected] = useState('');
  const [compareId, setCompareId] = useState('');
  const [comparing, setComparing] = useState(false);
  let parsed: string[] | undefined;
  try { parsed = validateTags(tags.trim() ? tags.split(',').map(tag => tag.trim()) : []); } catch (_) { /* invalid input */ }
  if (!page.incident_relations || !page.evidence_register) return <EuiText size='s'>Investigation register unavailable on this indexer version.</EuiText>;
  const relations = page.incident_relations, evidence = page.evidence_register;
  const compare = evidence.find(row => row.id === compareId);
  const blocked = disabled || page.activity_pending || page.observed_revision !== incident.revision;
  const safeTarget = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(target) && target !== incident.id;
  const changed = parsed && JSON.stringify(parsed) !== JSON.stringify([...(incident.tags ?? [])].sort());
  return <>
    <EuiTitle size='s'><h2>Investigation register</h2></EuiTitle>
    <EuiCallOut title='Shared analyst-authored metadata'>
      Do not copy restricted finding content, secrets or sensitive URLs. Evidence entries are external custody attestations, not uploaded or verified forensic files.
    </EuiCallOut>
    <EuiSpacer size='m' />
    <EuiFormRow label='Incident tags (comma separated)' helpText='Up to 25 unique lowercase tags, using letters, numbers, underscores and hyphens.' isInvalid={!parsed}>
      <EuiFieldText value={tags} maxLength={1650} disabled={blocked} onChange={e => setTags(e.target.value)} />
    </EuiFormRow>
    <EuiButton disabled={blocked || !changed} onClick={() => parsed && void command({ kind: 'set-tags', tags: parsed })}>Save tags</EuiButton>
    <EuiSpacer size='l' />
    <EuiTitle size='s'><h3>Related incident assertions ({relations.length}/50)</h3></EuiTitle>
    <EuiText size='s'>Directional analyst assertions only. Target existence, reciprocal links and duplicate classification are not verified or changed.</EuiText>
    {relations.map(row => <EuiPanel key={row.id} hasShadow={false} hasBorder>
      <EuiText size='s'><strong>{row.type.replace(/_/g, ' ')}</strong> · {row.target_id}<br />
        {row.reason}<br />{row.recorded_by} · {row.recorded_at}</EuiText>
      {openRelated && <EuiButtonEmpty onClick={() => openRelated(row.target_id)}>Open referenced incident</EuiButtonEmpty>}
      <EuiButtonEmpty disabled={blocked} onClick={() => { setSelected('relation:' + row.id); setReason(''); }}>Remove relation</EuiButtonEmpty>
    </EuiPanel>)}
    <EuiFormRow label='Related incident UUID'><EuiFieldText value={target} maxLength={36} disabled={blocked} onChange={e => setTarget(e.target.value)} /></EuiFormRow>
    <EuiFormRow label='Relationship type'><EuiSelect value={relation} disabled={blocked} options={RELATION_TYPES.map(value => ({ value, text: value.replace(/_/g, ' ') }))} onChange={e => setRelation(e.target.value as IncidentRelationType)} /></EuiFormRow>
    <EuiFormRow label='Relationship rationale'><EuiFieldText value={relationReason} maxLength={1024} disabled={blocked} onChange={e => setRelationReason(e.target.value)} /></EuiFormRow>
    <EuiButton disabled={blocked || !safeTarget || !relationReason.trim() || relations.length >= 50 || relations.some(row => row.target_id === target)}
      onClick={() => void command({ kind: 'add-relation', target_id: target, type: relation, reason: relationReason })}>Record relationship</EuiButton>
    <EuiSpacer size='l' />
    <EuiTitle size='s'><h3>External evidence manifest ({evidence.length}/50)</h3></EuiTitle>
    {evidence.map(row => <EuiPanel key={row.id} hasShadow={false} hasBorder>
      <EuiText size='s'><strong>{row.label}</strong> · {row.type.replace(/_/g, ' ')} · {row.state}<br />
        SHA-256: <code style={{ overflowWrap: 'anywhere' }}>{row.sha256}</code><br />
        Custody reference: {row.custody_reference}<br />
        Recorded by {row.recorded_by} · {row.recorded_at}
        {row.state === 'withdrawn' && <><br />Withdrawn by {row.withdrawn_by} · {row.withdrawn_at} · {row.withdrawal_reason}</>}</EuiText>
      {row.state === 'recorded' && <EuiButtonEmpty disabled={blocked} onClick={() => { setSelected('evidence:' + row.id); setReason(''); }}>Withdraw evidence attestation</EuiButtonEmpty>}
    </EuiPanel>)}
    {evidence.length > 0 && <>
      <EuiFormRow label='Evidence to compare locally'><EuiSelect value={compareId} disabled={comparing}
        options={[{ value: '', text: 'Select an attestation' }, ...evidence.map(row => ({ value: row.id, text: row.label + ' · ' + row.id }))]}
        onChange={e => setCompareId(e.target.value)} /></EuiFormRow>
      {compare && <LocalEvidenceVerifier key={compare.id} evidence={compare} onBusy={setComparing} />}
    </>}
    <EuiFormRow label='Artifact type'><EuiSelect value={type} disabled={blocked} options={EVIDENCE_TYPES.map(value => ({ value, text: value.replace(/_/g, ' ') }))} onChange={e => setType(e.target.value as EvidenceArtifactType)} /></EuiFormRow>
    <EuiFormRow label='Artifact label'><EuiFieldText value={label} maxLength={256} disabled={blocked} onChange={e => setLabel(e.target.value)} /></EuiFormRow>
    <EuiFormRow label='Artifact SHA-256'><EuiFieldText value={digest} maxLength={64} disabled={blocked} onChange={e => setDigest(e.target.value)} /></EuiFormRow>
    <EuiFormRow label='External custody reference' helpText='Opaque reference to your separately controlled evidence store; no retrieval is performed.'><EuiFieldText value={custody} maxLength={256} disabled={blocked} onChange={e => setCustody(e.target.value)} /></EuiFormRow>
    <EuiButton disabled={blocked || !label.trim() || !custody.trim() || !/^[a-f0-9]{64}$/.test(digest) || evidence.length >= 50 ||
        evidence.some(row => row.sha256 === digest && row.custody_reference === custody.trim())}
      onClick={() => void command({ kind: 'register-evidence', type, label, sha256: digest, custody_reference: custody })}>Register external evidence</EuiButton>
    {selected && <>
      <EuiSpacer size='m' />
      <EuiText size='s'>Selected record: {selected}</EuiText>
      <EuiFormRow label='Removal or withdrawal reason'><EuiFieldText value={reason} maxLength={1024} disabled={blocked} onChange={e => setReason(e.target.value)} /></EuiFormRow>
      <EuiButton color='danger' disabled={blocked || !reason.trim()} onClick={() => {
        if (selected.startsWith('relation:')) void command({ kind: 'remove-relation', relation_id: selected.slice(9), reason });
        else void command({ kind: 'withdraw-evidence', evidence_id: selected.slice(9), reason });
      }}>Confirm removal or withdrawal</EuiButton>
      <EuiButtonEmpty onClick={() => { setSelected(''); setReason(''); }}>Cancel selection</EuiButtonEmpty>
    </>}
    <EuiSpacer size='l' />
  </>;
}
