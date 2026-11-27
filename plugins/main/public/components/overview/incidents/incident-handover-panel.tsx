import React, { useState } from 'react';
import { EuiButton, EuiCallOut, EuiFieldText, EuiFormRow, EuiSpacer, EuiText, EuiTextArea, EuiTitle } from '@elastic/eui';
import type { IncidentSummary, IndexerIncidentCommand } from '../../../../common/incidents/contracts';

export function IncidentHandoverPanel({ incident, disabled, command }: {
  incident: IncidentSummary; disabled: boolean; command: (value: IndexerIncidentCommand) => Promise<void>;
}) {
  const [target, setTarget] = useState('');
  const [reason, setReason] = useState('');
  if (!incident.owner || incident.status === 'closed' || incident.handover === undefined) return null;
  const offer = incident.handover;
  return <>
    <EuiTitle size='s'><h2>Analyst handover</h2></EuiTitle>
    <EuiText size='s'>The current owner retains responsibility until the exact authenticated recipient accepts. The assignment grant and participant checks are enforced by the indexer. Usernames are not directory-verified when offered. Reasons are recorded in internal audit; use an investigation note for shared handover context.</EuiText>
    {offer ? <EuiCallOut title={'Pending handover to ' + offer.target}>
      Offered by {offer.offered_by} at {offer.offered_at}. Accept as the named recipient, or cancel as either participant.
    </EuiCallOut> : <EuiFormRow label='Recipient exact username'>
      <EuiFieldText value={target} maxLength={1024} disabled={disabled} onChange={e => setTarget(e.target.value)} />
    </EuiFormRow>}
    <EuiFormRow label='Handover reason'><EuiTextArea value={reason} maxLength={8192} disabled={disabled} onChange={e => setReason(e.target.value)} /></EuiFormRow>
    {offer ? <>
      <EuiButton disabled={disabled || !reason.trim()} onClick={() => void command({ kind: 'accept-handover', reason })}>Accept handover</EuiButton>{' '}
      <EuiButton disabled={disabled || !reason.trim()} onClick={() => void command({ kind: 'cancel-handover', reason })}>Cancel or decline handover</EuiButton>
    </> : <EuiButton disabled={disabled || !target.trim() || target !== target.trim() || target === incident.owner || !reason.trim()}
      onClick={() => void command({ kind: 'offer-handover', target, reason })}>Offer handover</EuiButton>}
    <EuiSpacer size='m' />
  </>;
}
