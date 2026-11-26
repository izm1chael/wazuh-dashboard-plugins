import React, { useEffect, useState } from 'react';
import { EuiButton, EuiButtonEmpty, EuiCallOut, EuiFieldText, EuiFormRow, EuiPanel, EuiSelect, EuiSpacer, EuiText, EuiTextArea, EuiTitle } from '@elastic/eui';
import type { IncidentResponsePage, IncidentResponseRecord, IncidentSummary, IndexerIncidentCommand, ManualResponseOutcome, ResponseIntent } from '../../../../common/incidents/contracts';
import { RESPONSE_INTENTS, RESPONSE_OUTCOMES } from '../../../../common/incidents/response-validation';
import type { IncidentApi } from './incident-api';

const label = (value: string) => value.replace(/_/g, ' ');
type Decision = 'approve-response' | 'reject-response' | 'cancel-response' | 'record-response-outcome';

function ResponseRow({ row, disabled, owner, command }: {
  row: IncidentResponseRecord; disabled: boolean; owner: boolean; command: (value: IndexerIncidentCommand) => Promise<void>;
}) {
  const [reason, setReason] = useState('');
  const [outcome, setOutcome] = useState<ManualResponseOutcome>('not_performed');
  const pending = row.state === 'requested';
  const approved = row.state === 'approved';
  const submit = (kind: Decision) => {
    if (disabled || !reason.trim()) return;
    const common = { response_id: row.id, reason };
    if (kind === 'record-response-outcome') void command({ kind, ...common, outcome });
    else void command({ kind, ...common });
  };
  return <EuiPanel paddingSize='m' hasShadow={false} hasBorder>
    <EuiText size='s'>
      <p><strong>{label(row.type)}</strong> · {label(row.state)} · Execution not verified</p>
      <p>Scope: {row.scope}</p><p>Reason: {row.reason}</p>
      <p>Requested by {row.requested_by} · {row.requested_at}</p>
      {row.decided_by && <p>Decision by {row.decided_by} · {row.decided_at} · {row.decision_reason}</p>}
      {row.finalized_by && <p>Finalized by {row.finalized_by} · {row.finalized_at} · {row.final_reason}</p>}
    </EuiText>
    {!disabled && (pending || approved) && <>
      <EuiFormRow label={'Decision or outcome reason for ' + row.id}><EuiTextArea value={reason} maxLength={2048} onChange={event => setReason(event.target.value)} /></EuiFormRow>
      {pending && <>
        <EuiButtonEmpty disabled={!reason.trim()} onClick={() => submit('approve-response')}>Approve request</EuiButtonEmpty>
        <EuiButtonEmpty disabled={!reason.trim()} onClick={() => submit('reject-response')}>Reject request</EuiButtonEmpty>
      </>}
      {approved && <>
        <EuiFormRow label='Manual outcome'><EuiSelect value={outcome} options={RESPONSE_OUTCOMES.map(value => ({ value, text: label(value) }))} onChange={e => setOutcome(e.target.value as ManualResponseOutcome)} /></EuiFormRow>
        <EuiButtonEmpty disabled={!reason.trim()} onClick={() => submit('record-response-outcome')}>Record unverified outcome</EuiButtonEmpty>
      </>}
      {owner && <EuiButtonEmpty disabled={!reason.trim()} onClick={() => submit('cancel-response')}>Cancel request</EuiButtonEmpty>}
    </>}
  </EuiPanel>;
}

export function IncidentResponsePanel({ api, incident, disabled, command }: {
  api: IncidentApi; incident: IncidentSummary; disabled: boolean; command: (value: IndexerIncidentCommand) => Promise<void>;
}) {
  const [page, setPage] = useState<IncidentResponsePage>();
  const [error, setError] = useState(false);
  const [loading, setLoading] = useState(true);
  const [refresh, setRefresh] = useState(0);
  const [type, setType] = useState<ResponseIntent>('investigate_endpoint');
  const [scope, setScope] = useState('');
  const [reason, setReason] = useState('');
  useEffect(() => {
    let current = true;
    setPage(undefined); setError(false); setLoading(true);
    api.responses(incident.id).then(result => { if (current) setPage(result); },
      () => { if (current) setError(true); }).finally(() => { if (current) setLoading(false); });
    return () => { current = false; };
  }, [api, incident.id, refresh]);
  const stale = !!page && page.observed_revision !== incident.revision;
  const blocked = disabled || loading || error || stale || !page || page.activity_pending;
  const canRequest = !blocked && !!incident.owner && ['triaging', 'active'].includes(incident.status) &&
    (page?.responses.length ?? 50) < 50;
  return <>
    <EuiTitle size='s'><h2>Response governance</h2></EuiTitle>
    <EuiSpacer size='s' />
    <EuiCallOut title='Manual tracking only'>Approval does not dispatch a response. Reported outcomes are not verified endpoint execution. Permissions and independent reviewer checks are enforced by the indexer.</EuiCallOut>
    <EuiButtonEmpty disabled={loading || disabled} onClick={() => setRefresh(value => value + 1)}>Refresh response records</EuiButtonEmpty>
    {error && <EuiText size='s'>Response records unavailable or access denied.</EuiText>}
    {loading && <EuiText size='s'>Loading response records…</EuiText>}
    {stale && <EuiCallOut color='warning' title='Incident revision changed'>Reload the incident before changing response records.</EuiCallOut>}
    {page?.activity_pending && <EuiCallOut color='warning' title='Response changes blocked while activity delivery is pending' />}
    {page && <>
      <EuiText size='s'><p>{page.responses.length} of 50 response records. Resolve or cancel outstanding requests before closing the incident.</p></EuiText>
      {page.responses.map(row => <React.Fragment key={row.id}>
        <ResponseRow row={row} disabled={blocked} owner={!!incident.owner} command={command} />
        <EuiSpacer size='s' />
      </React.Fragment>)}
      {canRequest && <form onSubmit={event => {
        event.preventDefault();
        if (canRequest && scope.trim() && reason.trim()) void command({ kind: 'request-response', type, scope, reason });
      }}>
        <EuiFormRow label='Response intent'><EuiSelect value={type} options={RESPONSE_INTENTS.map(value => ({ value, text: label(value) }))} onChange={e => setType(e.target.value as ResponseIntent)} /></EuiFormRow>
        <EuiFormRow label='Response scope' helpText='Human-readable scope, not an executable target or command.'><EuiFieldText maxLength={512} value={scope} onChange={e => setScope(e.target.value)} /></EuiFormRow>
        <EuiFormRow label='Response request reason'><EuiTextArea maxLength={2048} value={reason} onChange={e => setReason(e.target.value)} /></EuiFormRow>
        <EuiButton type='submit' disabled={!scope.trim() || !reason.trim()}>Request response review</EuiButton>
      </form>}
    </>}
  </>;
}
