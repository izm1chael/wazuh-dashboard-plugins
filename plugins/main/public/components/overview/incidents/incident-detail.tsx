import React, { useEffect, useRef, useState } from 'react';
import { EuiButton, EuiButtonEmpty, EuiCallOut, EuiDescriptionList, EuiFlexGroup, EuiFlexItem, EuiFormRow, EuiSelect, EuiSpacer, EuiText, EuiTextArea, EuiTitle } from '@elastic/eui';
import type { Classification, IncidentSummary, IndexerIncidentCommand } from '../../../../common/incidents/contracts';
import type { IncidentApi } from './incident-api';
import { IncidentActivityPanel } from './incident-activity-panel';
import { IncidentFindingsPanel } from './incident-findings-panel';
import { IncidentMetadataEditor } from './incident-metadata-editor';

export function IncidentDetail({ api, id, back }: { api: IncidentApi; id: string; back: () => void }) {
  const [incident, setIncident] = useState<IncidentSummary>();
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [mustReload, setMustReload] = useState(false);
  const [pending, setPending] = useState(false);
  const [refresh, setRefresh] = useState(0);
  const [reason, setReason] = useState('');
  const [classification, setClassification] = useState<Classification>('undetermined');
  const inFlight = useRef(false);

  useEffect(() => {
    let current = true;
    setLoading(true);
    setError('');
    api.get(id).then(record => {
      if (current) { setIncident(record); setMustReload(false); }
    }, () => {
      if (current) { setError('Incident unavailable or access denied.'); setMustReload(true); }
    }).finally(() => { if (current) setLoading(false); });
    return () => { current = false; };
  }, [api, id, refresh]);

  async function command(value: IndexerIncidentCommand) {
    if (!incident || loading || mustReload || inFlight.current) return;
    inFlight.current = true;
    setBusy(true);
    setError('');
    try {
      const result = await api.command(id, incident.revision, value);
      setIncident(result.incident);
      setPending(result.activity_delivery === 'pending');
      setReason('');
    } catch (_) {
      setError('The change could not be confirmed. Reload the incident before another operation.');
      setMustReload(true);
    } finally {
      inFlight.current = false;
      setBusy(false);
    }
  }

  const disabled = busy || loading || mustReload;
  return <>
    <EuiFlexGroup alignItems='center'>
      <EuiFlexItem><EuiButtonEmpty onClick={back} disabled={busy}>Back to incidents</EuiButtonEmpty></EuiFlexItem>
      <EuiFlexItem grow={false}><EuiButton onClick={() => setRefresh(value => value + 1)} disabled={busy || loading}>Reload incident</EuiButton></EuiFlexItem>
    </EuiFlexGroup>
    {error && <EuiCallOut color='danger' title={error} />}
    {pending && <EuiCallOut color='warning' title='Change saved; audit delivery was pending'>The recovery worker retries delivery. This notice reflects the last mutation response, not current delivery status.</EuiCallOut>}
    {loading && <EuiText>Loading incident…</EuiText>}
    {incident && <>
      <EuiTitle size='l'><h1>{incident.title}</h1></EuiTitle>
      <EuiText size='s'>{incident.id} · Revision {incident.revision}</EuiText>
      <EuiSpacer size='m' />
      <EuiDescriptionList type='column' listItems={[
        { title: 'Status', description: incident.status },
        { title: 'Severity', description: incident.severity },
        { title: 'Priority', description: incident.priority },
        { title: 'Owner', description: incident.owner || 'Unassigned' },
        { title: 'Created by', description: incident.created_by },
        { title: 'Created (UTC)', description: incident.created_at },
        { title: 'Updated by', description: incident.updated_by },
        { title: 'Updated (UTC)', description: incident.updated_at },
        { title: 'TLP', description: incident.tlp },
        { title: 'Findings', description: String(incident.finding_count) },
      ]} />
      <EuiSpacer size='m' />
      <EuiTitle size='s'><h2>Description</h2></EuiTitle>
      <EuiText><p style={{ whiteSpace: 'pre-wrap' }}>{incident.description || 'No description'}</p></EuiText>
      <EuiSpacer size='m' />
      <EuiTitle size='s'><h2>Workflow</h2></EuiTitle>
      <EuiText size='s'>Actions are enforced by indexer permissions and ownership.</EuiText>
      <EuiSpacer size='s' />
      <EuiFlexGroup wrap>
        {!incident.owner && incident.status === 'new' && <EuiFlexItem grow={false}><EuiButton disabled={disabled} onClick={() => command({ kind: 'assign-self' })}>Claim incident</EuiButton></EuiFlexItem>}
        {incident.owner && incident.status === 'new' && <>
          <EuiFlexItem grow={false}><EuiButton disabled={disabled} onClick={() => command({ kind: 'start-triage' })}>Start triage</EuiButton></EuiFlexItem>
          <EuiFlexItem grow={false}><EuiButton disabled={disabled} onClick={() => command({ kind: 'unassign' })}>Return to queue</EuiButton></EuiFlexItem>
        </>}
        {incident.status === 'triaging' && <EuiFlexItem grow={false}><EuiButton disabled={disabled} onClick={() => command({ kind: 'activate' })}>Begin investigation</EuiButton></EuiFlexItem>}
      </EuiFlexGroup>
      {incident.closure && <EuiDescriptionList listItems={[
        { title: 'Classification', description: incident.closure.classification },
        { title: 'Closure reason', description: incident.closure.reason },
        { title: 'Closed by', description: incident.closure.closed_by },
      ]} />}
      {['triaging', 'active', 'closed'].includes(incident.status) && <>
        <EuiSpacer size='m' />
        {incident.status !== 'closed' && <EuiFormRow label='Closure classification'><EuiSelect value={classification} disabled={disabled}
          options={['true_positive', 'benign_positive', 'false_positive', 'undetermined', 'duplicate'].map(value => ({ value, text: value.replace(/_/g, ' ') }))}
          onChange={e => setClassification(e.target.value as Classification)} /></EuiFormRow>}
        <EuiFormRow label={incident.status === 'closed' ? 'Reopening reason' : 'Closure reason'}><EuiTextArea value={reason} disabled={disabled} maxLength={8192} onChange={e => setReason(e.target.value)} /></EuiFormRow>
        <EuiButton disabled={disabled || !reason.trim()} onClick={() => command(incident.status === 'closed' ? { kind: 'reopen', reason } : { kind: 'close', classification, reason })}>
          {incident.status === 'closed' ? 'Reopen incident' : 'Close incident'}
        </EuiButton>
      </>}
      <EuiSpacer size='l' />
      {incident.owner && incident.status !== 'closed' && <IncidentMetadataEditor key={id + ':' + incident.revision} incident={incident} disabled={disabled} command={command} />}
      <EuiSpacer size='l' />
      <IncidentFindingsPanel key={id + ':' + incident.revision + ':' + refresh} api={api} incident={incident} disabled={disabled || incident.status === 'closed' || !incident.owner} command={command} />
      <EuiSpacer size='l' />
      <IncidentActivityPanel key={id + ':' + incident.revision + ':' + refresh} api={api} id={id} />
    </>}
  </>;
}
