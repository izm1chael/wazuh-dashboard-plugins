import React, { useEffect, useState } from 'react';
import { EuiBasicTable, EuiBasicTableColumn, EuiButton, EuiButtonEmpty, EuiCallOut, EuiFieldText, EuiFlexGroup, EuiFlexItem, EuiFormRow, EuiSpacer, EuiText, EuiTitle } from '@elastic/eui';
import type { FindingPage, FindingReference, IncidentSummary, IndexerIncidentCommand } from '../../../../common/incidents/contracts';
import type { IncidentApi } from './incident-api';
import { FindingIntelligencePanel } from './finding-intelligence-panel';

export function IncidentFindingsPanel({ api, incident, disabled, command }: {
  api: IncidentApi; incident: IncidentSummary; disabled: boolean; command: (value: IndexerIncidentCommand) => Promise<void>;
}) {
  const [page, setPage] = useState<FindingPage>();
  const [offsets, setOffsets] = useState([0]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);
  const [reload, setReload] = useState(0);
  const [index, setIndex] = useState('');
  const [documentId, setDocumentId] = useState('');
  const offset = offsets[offsets.length - 1];
  useEffect(() => {
    let current = true;
    setPage(undefined); setError(false); setLoading(true);
    api.findings(incident.id, offset, incident.revision).then(result => { if (current) setPage(result); },
      () => { if (current) setError(true); }).finally(() => { if (current) setLoading(false); });
    return () => { current = false; };
  }, [api, incident.id, incident.revision, offset, reload]);

  const columns: Array<EuiBasicTableColumn<FindingReference>> = [
    { field: 'index', name: 'Finding index' },
    { field: 'document_id', name: 'Document ID' },
    { name: 'Actions', render: (ref: FindingReference) => <EuiButtonEmpty color='danger' disabled={disabled}
        onClick={() => command({ kind: 'detach-finding', ...ref })}>Detach finding</EuiButtonEmpty> },
  ];
  return <>
    <EuiTitle size='s'><h2>Linked findings ({incident.finding_count})</h2></EuiTitle>
    <EuiSpacer size='s' />
    <EuiText size='s'>Only findings accessible with your current permissions are displayed. Links are not retained evidence copies.</EuiText>
    {error && <EuiCallOut color='danger' title='Linked findings unavailable'>Reload the incident if it changed.</EuiCallOut>}
    {!!page?.unavailable_count && <EuiCallOut color='warning' title={page.unavailable_count + ' unavailable finding(s) on this page'}>Findings may have expired or be inaccessible. Individual restricted identifiers are not shown.</EuiCallOut>}
    <EuiBasicTable<FindingReference> items={page?.findings ?? []} columns={columns} loading={loading} noItemsMessage='No visible findings on this page' />
    <EuiFlexGroup>
      <EuiFlexItem><EuiText size='s'>Page {offsets.length}</EuiText></EuiFlexItem>
      <EuiFlexItem grow={false}><EuiButtonEmpty disabled={loading} onClick={() => { setOffsets([0]); setReload(value => value + 1); }}>Refresh findings</EuiButtonEmpty></EuiFlexItem>
      <EuiFlexItem grow={false}><EuiButtonEmpty disabled={loading || offsets.length === 1} onClick={() => setOffsets(items => items.slice(0, -1))}>Previous findings</EuiButtonEmpty></EuiFlexItem>
      <EuiFlexItem grow={false}><EuiButtonEmpty disabled={loading || page?.next_offset === undefined} onClick={() => { const next = page?.next_offset; if (next !== undefined) setOffsets(items => [...items, next]); }}>Next findings</EuiButtonEmpty></EuiFlexItem>
    </EuiFlexGroup>
    <EuiSpacer size='m' />
    {page?.observations !== undefined && <FindingIntelligencePanel observations={page.observations} />}
    <EuiSpacer size='s' />
    <form onSubmit={event => {
      event.preventDefault();
      if (!disabled && index.trim() && documentId.trim()) void command({ kind: 'attach-finding', index: index.trim(), document_id: documentId });
    }}>
      <EuiFlexGroup alignItems='flexEnd' wrap>
        <EuiFlexItem><EuiFormRow label='Concrete finding index'><EuiFieldText value={index} disabled={disabled} maxLength={255} onChange={event => setIndex(event.target.value)} /></EuiFormRow></EuiFlexItem>
        <EuiFlexItem><EuiFormRow label='Finding document ID'><EuiFieldText value={documentId} disabled={disabled} maxLength={512} onChange={event => setDocumentId(event.target.value)} /></EuiFormRow></EuiFlexItem>
        <EuiFlexItem grow={false}><EuiButton type='submit' disabled={disabled || !index.trim() || !documentId.trim()}>Attach finding</EuiButton></EuiFlexItem>
      </EuiFlexGroup>
    </form>
  </>;
}
