import React, { useState } from 'react';
import { EuiAccordion, EuiButton, EuiFieldText, EuiFormRow, EuiSelect, EuiSpacer, EuiTextArea } from '@elastic/eui';
import type { IncidentSummary, IndexerIncidentCommand, Severity, Priority, Tlp } from '../../../../common/incidents/contracts';

export function IncidentMetadataEditor({ incident, disabled, command }: {
  incident: IncidentSummary; disabled: boolean; command: (value: IndexerIncidentCommand) => Promise<void>;
}) {
  const [title, setTitle] = useState(incident.title);
  const [description, setDescription] = useState(incident.description);
  const [severity, setSeverity] = useState(incident.severity);
  const [priority, setPriority] = useState(incident.priority);
  const [tlp, setTlp] = useState(incident.tlp);
  const changes = {
    ...(title.trim() !== incident.title ? { title } : {}),
    ...(description !== incident.description ? { description } : {}),
    ...(severity !== incident.severity ? { severity } : {}),
    ...(priority !== incident.priority ? { priority } : {}),
    ...(tlp !== incident.tlp ? { tlp } : {}),
  };
  const canSave = !disabled && !!title.trim() && Object.keys(changes).length > 0;
  const options = (values: string[]) => values.map(value => ({ value, text: value }));
  return <EuiAccordion id={'incident-edit-' + incident.id} buttonContent='Edit incident metadata'>
    <EuiSpacer size='s' />
    <form onSubmit={event => { event.preventDefault(); if (canSave) void command({ kind: 'edit', ...changes }); }}>
      <EuiFormRow label='Title'><EuiFieldText value={title} maxLength={1024} disabled={disabled} onChange={e => setTitle(e.target.value)} /></EuiFormRow>
      <EuiFormRow label='Description'><EuiTextArea value={description} maxLength={32768} disabled={disabled} onChange={e => setDescription(e.target.value)} /></EuiFormRow>
      <EuiFormRow label='Severity'><EuiSelect value={severity} disabled={disabled} options={options(['informational', 'low', 'medium', 'high', 'critical'])} onChange={e => setSeverity(e.target.value as Severity)} /></EuiFormRow>
      <EuiFormRow label='Priority'><EuiSelect value={priority} disabled={disabled} options={options(['low', 'medium', 'high', 'urgent'])} onChange={e => setPriority(e.target.value as Priority)} /></EuiFormRow>
      <EuiFormRow label='TLP'><EuiSelect value={tlp} disabled={disabled} options={options(['TLP:CLEAR', 'TLP:GREEN', 'TLP:AMBER', 'TLP:AMBER+STRICT', 'TLP:RED'])} onChange={e => setTlp(e.target.value as Tlp)} /></EuiFormRow>
      <EuiButton type='submit' disabled={!canSave}>Save metadata</EuiButton>
    </form>
  </EuiAccordion>;
}
