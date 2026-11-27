import React, { useEffect, useRef, useState } from 'react';
import { EuiButton, EuiButtonEmpty, EuiCallOut, EuiCheckbox, EuiFieldText, EuiFormRow, EuiPanel, EuiSelect, EuiSpacer, EuiText, EuiTextArea, EuiTitle } from '@elastic/eui';
import type { CollaborationPage, IncidentSummary, IndexerIncidentCommand, TuningProposal, TuningType } from '../../../../common/incidents/contracts';
import { parseReplay, evaluateReplay } from '../../../../common/incidents/tuning-evaluation';
import { PROPOSAL_ROWS, SHA256, TUNING_TYPES, validateTuningProposals } from '../../../../common/incidents/tuning-proposal-validation';
import { RULE_UUID } from '../../../../common/incidents/rule-history';
import type { IncidentApi } from './incident-api';
const human = (value: string) => value.replace(/_/g, ' ');
const percent = (n: number, d: number) => d ? (100 * n / d).toFixed(1) + '%' : 'Not available';

function Proposal({ row, disabled, command }: { row: TuningProposal; disabled: boolean; command: (value: IndexerIncidentCommand) => Promise<void> }) {
  const [reason, setReason] = useState('');
  const [digest, setDigest] = useState('');
  const [attest, setAttest] = useState(false);
  const [submitted, setSubmitted] = useState(false);
  const replay = row.replay;
  const review = (decision: 'accepted_for_review' | 'rejected') => {
    if (disabled || submitted || !attest || digest !== replay.fixture_sha256 || !reason.trim() ||
        (decision === 'accepted_for_review' && replay.gate !== 'eligible_for_human_review')) return;
    setSubmitted(true);
    void command({ kind: 'review-tuning-proposal', proposal_id: row.id, decision, fixture_sha256: digest, reason });
  };
  return <EuiPanel hasBorder hasShadow={false} paddingSize='m'>
    <EuiText size='s'>
      <h4>{human(row.type)} · {human(row.state)}</h4>
      <p>Analyst-supplied rule UUID: {row.rule_uuid}. Baseline SHA-256: {row.baseline_sha256}. Candidate SHA-256: {row.candidate_sha256}.</p>
      <p>Proposed by {row.proposed_by} at {row.proposed_at}. {row.reason}</p>
      <p>Fixture SHA-256: {replay.fixture_sha256}. {replay.total} samples ({replay.malicious} malicious, {replay.benign} benign, {replay.unknown} unknown).</p>
      <p>Recall: {percent(replay.baseline_tp, replay.malicious)} → {percent(replay.candidate_tp, replay.malicious)}.
        False-positive rate: {percent(replay.baseline_fp, replay.benign)} → {percent(replay.candidate_fp, replay.benign)}.</p>
      <p>Lost malicious: {replay.lost_malicious}; gained: {replay.gained_malicious}. Removed benign: {replay.removed_benign}; added: {replay.added_benign}. Gate: {human(replay.gate)}.</p>
      {row.decided_by && <p>Decision by {row.decided_by} at {row.decided_at}: {row.decision_reason}.</p>}
    </EuiText>
    {row.state === 'proposed' && <>
      <EuiFormRow label='Review or withdrawal reason'><EuiTextArea maxLength={2048} value={reason} disabled={disabled || submitted} onChange={e => setReason(e.target.value)} /></EuiFormRow>
      <EuiFormRow label='Independently checked fixture SHA-256'><EuiFieldText maxLength={64} value={digest} disabled={disabled || submitted} onChange={e => setDigest(e.target.value)} /></EuiFormRow>
      <EuiCheckbox id={'tuning-review-' + row.id} checked={attest} disabled={disabled || submitted}
        label='I reviewed the external evidence; this decision does not authorize deployment' onChange={e => setAttest(e.target.checked)} />
      <EuiButtonEmpty disabled={disabled || submitted || !attest || digest !== replay.fixture_sha256 || !reason.trim() || replay.gate !== 'eligible_for_human_review'}
        onClick={() => review('accepted_for_review')}>Accept for human review</EuiButtonEmpty>
      <EuiButtonEmpty disabled={disabled || submitted || !attest || digest !== replay.fixture_sha256 || !reason.trim()}
        onClick={() => review('rejected')}>Reject proposal</EuiButtonEmpty>
      <EuiButtonEmpty disabled={disabled || submitted || !reason.trim()} onClick={() => {
        if (disabled || submitted || !reason.trim()) return;
        setSubmitted(true); void command({ kind: 'withdraw-tuning-proposal', proposal_id: row.id, reason });
      }}>Withdraw proposal</EuiButtonEmpty>
    </>}
  </EuiPanel>;
}

export function IncidentTuningGovernancePanel({ incident, api, disabled, command }: {
  incident: IncidentSummary; api: IncidentApi; disabled: boolean; command: (value: IndexerIncidentCommand) => Promise<void>;
}) {
  const [page, setPage] = useState<CollaborationPage>();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [fixture, setFixture] = useState('');
  const [rule, setRule] = useState('');
  const [reason, setReason] = useState('');
  const [type, setType] = useState<TuningType>('review_rule_scope');
  const [share, setShare] = useState(false);
  const [submitted, setSubmitted] = useState(false);
  const mounted = useRef(true), loading = useRef(false);
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; }; }, []);
  async function load() {
    if (disabled || loading.current) return;
    loading.current = true; setBusy(true); setError(''); setPage(undefined);
    try {
      const data = await api.collaboration(incident.id);
      validateTuningProposals(data, incident.id);
      if (mounted.current) setPage(data);
    } catch (_) { if (mounted.current) setError('Tuning proposals unavailable.'); }
    finally { loading.current = false; if (mounted.current) setBusy(false); }
  }
  const blocked = disabled || busy || !page || page.observed_revision !== incident.revision || page.activity_pending || submitted;
  const canCreate = !blocked && !!incident.owner && ['triaging', 'active', 'closed'].includes(incident.status) && (page?.tuning_proposals?.length ?? 25) < 25;
  async function create() {
    if (!canCreate || !share || !RULE_UUID.test(rule) || !reason.trim()) return;
    setError('');
    try {
      if (fixture.length > 240000) throw new Error('Fixture exceeds input budget');
      const parsed = parseReplay(JSON.parse(fixture));
      if (parsed.rows.length > PROPOSAL_ROWS || !SHA256.test(parsed.baseline_version) || !SHA256.test(parsed.candidate_version)) {
        throw new Error('Use distinct lowercase SHA-256 rule version hashes and at most 1000 rows');
      }
      evaluateReplay(parsed); // Local syntax/conservation check only; the indexer recomputes the gate.
      setSubmitted(true); setShare(false);
      await command({ kind: 'create-tuning-proposal', rule_uuid: rule, baseline_sha256: parsed.baseline_version,
        candidate_sha256: parsed.candidate_version, type, reason, split: parsed.split, rows: parsed.rows });
    } catch (e) { setError(e instanceof Error ? e.message : 'Proposal could not be confirmed'); }
  }
  return <>
    <EuiTitle size='s'><h2>Detection tuning proposals</h2></EuiTitle>
    <EuiText size='s'><p>Record and independently review externally executed replay evidence. Rule identity, version hashes, labels and holdout status are analyst attestations; the server recomputes the gate, but does not execute rules. No deployment action exists.</p></EuiText>
    <EuiButton disabled={disabled || busy || submitted} onClick={() => void load()}>Load tuning proposals</EuiButton>
    {error && <EuiCallOut color='warning' title={error} />}
    {page && page.observed_revision !== incident.revision && <EuiCallOut color='warning' title='Incident revision changed; reload before review' />}
    {page?.activity_pending && <EuiCallOut color='warning' title='Audit delivery pending' />}
    {page && page.tuning_proposals === undefined && <EuiText size='s'>Tuning proposal feature unavailable on this server.</EuiText>}
    {page?.tuning_proposals && <>
      <EuiText size='s'>{page.tuning_proposals.length} of 25 lifetime proposal records.</EuiText>
      {page.tuning_proposals.map(row => <React.Fragment key={row.id}><Proposal row={row} disabled={blocked} command={command} /><EuiSpacer size='s' /></React.Fragment>)}
      {canCreate && <>
        <EuiTitle size='xs'><h3>Submit a tuning proposal</h3></EuiTitle>
        <EuiFormRow label='Analyst-attested Wazuh rule UUID'><EuiFieldText maxLength={36} value={rule} onChange={e => setRule(e.target.value)} /></EuiFormRow>
        <EuiFormRow label='Review category'><EuiSelect value={type} options={TUNING_TYPES.map(value => ({ value, text: human(value) }))} onChange={e => setType(e.target.value as TuningType)} /></EuiFormRow>
        <EuiFormRow label='Reason and external fixture reference'><EuiTextArea maxLength={2048} value={reason} onChange={e => setReason(e.target.value)} /></EuiFormRow>
        <EuiFormRow label='Paired holdout fixture JSON' helpText='Same evaluator format; baseline_version and candidate_version must be SHA-256 hashes. Maximum 1000 rows. Keep external fixture for review. No raw logs.' fullWidth>
          <EuiTextArea fullWidth maxLength={240000} rows={8} value={fixture} onChange={e => setFixture(e.target.value)} /></EuiFormRow>
        <EuiCheckbox id={'tuning-share-' + incident.id} checked={share} label='Share proposal metadata and computed receipt with incident readers' onChange={e => setShare(e.target.checked)} />
        <EuiButton disabled={!share || !RULE_UUID.test(rule) || !reason.trim() || !fixture.trim()} onClick={() => void create()}>Record proposal</EuiButton>
      </>}
    </>}
  </>;
}
