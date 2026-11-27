import React, { useRef, useState } from 'react';
import { EuiButton, EuiButtonEmpty, EuiCallOut, EuiFieldText, EuiFormRow, EuiSelect, EuiSpacer, EuiTextArea, EuiTitle } from '@elastic/eui';
import type { CreateIncident, Severity } from '../../../../common/incidents/contracts';
import type { IncidentApi } from './incident-api';

function newRequestId(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  bytes[6] = (bytes[6] & 15) | 64;
  bytes[8] = (bytes[8] & 63) | 128;
  const hex = Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
  return [hex.slice(0, 8), hex.slice(8, 12), hex.slice(12, 16), hex.slice(16, 20), hex.slice(20)].join('-');
}

export function IncidentCreate({ api, back, open, generateId = newRequestId }: {
  api: IncidentApi; back: () => void; open: (id: string) => void; generateId?: () => string;
}) {
  const [title, setTitle] = useState('');
  const [description, setDescription] = useState('');
  const [severity, setSeverity] = useState<Severity>('medium');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(false);
  const [attempted, setAttempted] = useState(false);
  const inFlight = useRef(false);
  const attempt = useRef<{ key: string; payload: CreateIncident }>();

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    if (!title.trim() || inFlight.current) return;
    inFlight.current = true;
    setBusy(true);
    setError(false);
    try {
      if (!attempt.current) {
        attempt.current = { key: generateId(), payload: { title, description, severity } };
        setAttempted(true);
      }
      const result = await api.create(attempt.current.payload, attempt.current.key);
      open(result.incident.id);
    } catch (_) {
      setError(true);
    } finally {
      inFlight.current = false;
      setBusy(false);
    }
  }

  return <>
    <EuiButtonEmpty onClick={back} disabled={busy}>Back to incidents</EuiButtonEmpty>
    <EuiTitle size='l'><h1>Create incident</h1></EuiTitle>
    <EuiSpacer size='m' />
    {error && <EuiCallOut color='warning' title='Creation could not be confirmed'>
      Retry the same request to avoid duplicate incidents. If you leave this form, check the queue before creating another case.
    </EuiCallOut>}
    <form onSubmit={submit}>
      <EuiFormRow label='Incident title'><EuiFieldText value={title} maxLength={1024} disabled={attempted || busy} onChange={e => setTitle(e.target.value)} /></EuiFormRow>
      <EuiFormRow label='Description'><EuiTextArea value={description} maxLength={32768} disabled={attempted || busy} onChange={e => setDescription(e.target.value)} /></EuiFormRow>
      <EuiFormRow label='Severity'><EuiSelect value={severity} disabled={attempted || busy}
        options={['informational', 'low', 'medium', 'high', 'critical'].map(value => ({ value, text: value }))}
        onChange={e => setSeverity(e.target.value as Severity)} /></EuiFormRow>
      <EuiSpacer size='m' />
      <EuiButton type='submit' fill isLoading={busy} disabled={busy || !title.trim()}>{attempted ? 'Retry same request' : 'Create incident'}</EuiButton>
    </form>
  </>;
}
