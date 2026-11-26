import React, { useEffect, useState } from 'react';
import { EuiBasicTable, EuiBasicTableColumn, EuiButton, EuiButtonEmpty, EuiCallOut, EuiSpacer, EuiText, EuiTitle } from '@elastic/eui';
import type { IncidentSummary, IssuedResponsePage, IssuedResponseRecord } from '../../../../common/incidents/contracts';
import type { IncidentApi } from './incident-api';

export function IssuedResponsesPanel({ api, incident }: { api: IncidentApi; incident: IncidentSummary }) {
  const [enabled, setEnabled] = useState(false);
  const [page, setPage] = useState<IssuedResponsePage>();
  const [offsets, setOffsets] = useState([0]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(false);
  const [refresh, setRefresh] = useState(0);
  const offset = offsets[offsets.length - 1];
  useEffect(() => {
    if (!enabled) return;
    let current = true;
    setPage(undefined); setError(false); setLoading(true);
    api.issuedResponses(incident.id, offset, incident.revision).then(result => { if (current) setPage(result); },
      () => { if (current) setError(true); }).finally(() => { if (current) setLoading(false); });
    return () => { current = false; };
  }, [api, incident.id, incident.revision, offset, refresh, enabled]);
  const columns: Array<EuiBasicTableColumn<IssuedResponseRecord>> = [
    { field: 'issued_at', name: 'Issued (UTC)', render: (value: string | null) => value ?? 'Unknown' },
    { field: 'name', name: 'Configured response name', render: (value: string | null) => value ?? 'Unknown' },
    { field: 'type', name: 'Type' }, { field: 'location', name: 'Location' },
    { field: 'configured_agent_id', name: 'Configured agent' }, { field: 'source_agent_id', name: 'Source agent' },
    { name: 'Source finding', render: (record: IssuedResponseRecord) => <EuiText size='s'>{record.finding.index} / {record.finding.document_id}</EuiText> },
    { name: 'Outcome', render: () => 'Issued only — execution unverified' },
  ];
  return <>
    <EuiTitle size='s'><h2>Related Wazuh issued actions</h2></EuiTitle>
    <EuiSpacer size='s' />
    <EuiText size='s'>Live records linked by exact source finding index and document ID. Records may be missing due to retention, permissions or different source-reference formats. These records do not prove a governance request was dispatched or an endpoint action ran.</EuiText>
    {!enabled && <EuiButton onClick={() => setEnabled(true)}>Inspect related issued actions</EuiButton>}
    {enabled && <>
      {error && <EuiCallOut color='warning' title='Issued actions unavailable or incomplete'>Check stream access and reload the incident if its revision changed. An oversized result is not silently truncated.</EuiCallOut>}
      {page && <EuiText size='s'>{page.visible_finding_count} visible findings inspected on page {offsets.length}. {page.issued_responses.length} exact issued-action matches.</EuiText>}
      <EuiBasicTable<IssuedResponseRecord> items={page?.issued_responses ?? []} columns={columns} loading={loading}
        noItemsMessage='No visible exact issued-action matches on this page' />
      <EuiButtonEmpty disabled={loading} onClick={() => { setOffsets([0]); setRefresh(value => value + 1); }}>Refresh issued actions</EuiButtonEmpty>
      <EuiButtonEmpty disabled={loading || offsets.length === 1} onClick={() => setOffsets(items => items.slice(0, -1))}>Previous finding page</EuiButtonEmpty>
      <EuiButtonEmpty disabled={loading || page?.next_offset === undefined} onClick={() => {
        const next = page?.next_offset; if (next !== undefined) setOffsets(items => [...items, next]);
      }}>Next finding page</EuiButtonEmpty>
    </>}
  </>;
}
