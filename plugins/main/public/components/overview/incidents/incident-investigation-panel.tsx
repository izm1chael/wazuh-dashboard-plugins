import React, { useEffect, useRef, useState } from 'react';
import { EuiButton, EuiButtonEmpty, EuiCallOut, EuiFieldSearch, EuiFormRow, EuiSelect, EuiSpacer, EuiText, EuiTitle, EuiBasicTable, EuiBasicTableColumn } from '@elastic/eui';
import { HUNT_FIELDS, HuntField, validHuntValue } from '../../../../common/incidents/hunt-contract';
import { IncidentHuntPanel } from './incident-hunt-panel';
import type { IndexerIncidentCommand, IncidentSummary } from '../../../../common/incidents/contracts';
import type { IncidentApi } from './incident-api';
import { loadInvestigation, InvestigationSnapshot, TimelineRow } from './investigation-snapshot';
import { summarizeFindings } from './finding-intelligence-model';

export function IncidentInvestigationPanel({ api, incident, disabled, attach }: {
  api: IncidentApi; incident: IncidentSummary; disabled: boolean; attach?: (command: IndexerIncidentCommand) => Promise<void>;
}) {
  const [snapshot, setSnapshot] = useState<InvestigationSnapshot>();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(false);
  const [filter, setFilter] = useState('all');
  const [query, setQuery] = useState('');
  const [entity, setEntity] = useState('');
  const [hunt, setHunt] = useState<{ field: HuntField; value: string }>();
  const generation = useRef(0);
  useEffect(() => () => { generation.current++; }, []);
  async function load() {
    const run = ++generation.current;
    setSnapshot(undefined); setHunt(undefined); setLoading(true); setError(false); setEntity(''); setQuery(''); setFilter('all');
    try {
      const result = await loadInvestigation(api, incident, () => generation.current !== run);
      if (generation.current === run) setSnapshot(result);
    } catch (_) {
      if (generation.current === run) setError(true);
    } finally {
      if (generation.current === run) setLoading(false);
    }
  }
  function clear() {
    generation.current++; setSnapshot(undefined); setHunt(undefined); setLoading(false); setError(false);
    setEntity(''); setQuery(''); setFilter('all');
  }
  const intelligence = snapshot && summarizeFindings(snapshot.observations);
  const selectedEntity = intelligence?.entities.find(e => JSON.stringify([e.kind, e.value]) === entity);
  const huntFields = HUNT_FIELDS.filter(field => selectedEntity?.fields.includes(field) && validHuntValue(field, selectedEntity.value));
  const entityKeys = new Set(snapshot?.observations.filter(f =>
    f.entities.some(e => JSON.stringify([e.kind, e.value]) === entity)
  ).map(f => 'finding:' + JSON.stringify([f.index, f.document_id])));
  const rows = (snapshot?.rows ?? []).filter(row =>
    (filter === 'all' || row.source === filter) &&
    (!entity || (row.source === 'finding' && entityKeys.has(row.key))) &&
    (!query.trim() || (row.label + ' ' + row.detail).toLowerCase().includes(query.trim().toLowerCase())));
  const columns: Array<EuiBasicTableColumn<TimelineRow>> = [
    { field: 'at', name: 'Time (UTC)', render: (value: string | null) => value && Number.isFinite(Date.parse(value)) ? value : 'Unknown' },
    { field: 'source', name: 'Source' },
    { field: 'label', name: 'Event' },
    { field: 'detail', name: 'Reference / actor' },
  ];
  return <>
    <EuiTitle size='s'><h2>Incident investigation timeline</h2></EuiTitle>
    <EuiText size='s'>Combine current caller-visible linked finding observations and delivered analyst activity. This is an on-demand bounded view, not retained evidence or an atomic authorization snapshot. Up to 100 finding positions and 200 activity events are scanned; finding positions are not selected by time.</EuiText>
    <EuiSpacer size='s' />
    <EuiButton disabled={disabled || loading} onClick={() => void load()}>Load investigation view</EuiButton>
    <EuiButtonEmpty disabled={!loading && !snapshot && !error} onClick={clear}>Clear investigation view</EuiButtonEmpty>
    {loading && <EuiText size='s'>Loading bounded investigation pages…</EuiText>}
    {error && <EuiCallOut color='danger' title='Investigation view unavailable'>No partial rows retained. Reload the incident, check access and try again.</EuiCallOut>}
    {snapshot && intelligence && <>
      <EuiSpacer size='s' />
      <EuiText size='s'>Revision {snapshot.revision}: {snapshot.positions} positions scanned, {snapshot.observations.length} visible observations, {snapshot.unavailable} unavailable, {snapshot.unscanned} unscanned; {snapshot.events.length} delivered activity events.</EuiText>
      {(snapshot.unavailable > 0 || snapshot.unscanned > 0 || snapshot.activityPending || snapshot.activityCapped || snapshot.missingAuditRevisions > 0) &&
        <EuiCallOut color='warning' title='Investigation coverage is incomplete'>
          Missing audit revisions in scanned scope: {snapshot.missingAuditRevisions}. Audit pending: {String(snapshot.activityPending)}. Older activity beyond budget: {String(snapshot.activityCapped)}. Unavailable and unscanned findings are not evidence of absence.
        </EuiCallOut>}
      <EuiSpacer size='s' />
      <EuiText size='s'>Observed ATT&amp;CK techniques: {intelligence.techniques.join(', ') || 'None in visible observations'}. Tactics: {intelligence.tactics.join(', ') || 'None in visible observations'}.</EuiText>
      <EuiText size='s'>Entity menu: {Math.min(intelligence.entities.length, 250)} of {intelligence.entities.length} distinct visible entities, ranked by observed frequency. Use timeline text filtering for references.</EuiText>
      <EuiFormRow label='Observed entity pivot'>
        <EuiSelect value={entity} onChange={e => { setEntity(e.target.value); setHunt(undefined); setFilter('all'); }}
          options={[{ value: '', text: 'All visible entities' }, ...intelligence.entities.slice(0, 250).map(e => ({
            value: JSON.stringify([e.kind, e.value]), text: e.kind + ': ' + e.value + ' (' + e.count + ')',
          }))]} />
      </EuiFormRow>
      {selectedEntity && huntFields.map(field => <EuiButtonEmpty key={field} disabled={disabled}
        onClick={() => setHunt({ field, value: selectedEntity.value })}>Prepare hunt: {field}</EuiButtonEmpty>)}
      {hunt && <>
        <EuiButtonEmpty onClick={() => setHunt(undefined)}>Close hunt</EuiButtonEmpty>
        <IncidentHuntPanel key={JSON.stringify(hunt)} initial={hunt} disabled={disabled}
          attach={incident.owner && incident.status !== 'closed' ? attach : undefined} />
      </>}
      <EuiFormRow label='Timeline source'><EuiSelect value={filter} disabled={!!entity} onChange={e => setFilter(e.target.value)}
        options={[{ value: 'all', text: 'All sources' }, { value: 'finding', text: 'Finding observations' }, { value: 'activity', text: 'Analyst activity' }]} /></EuiFormRow>
      <EuiFormRow label='Filter visible timeline rows'><EuiFieldSearch value={query} onChange={e => setQuery(e.target.value)} /></EuiFormRow>
      <EuiBasicTable<TimelineRow> items={rows} columns={columns} itemId='key' noItemsMessage='No matching visible rows' />
    </>}
  </>;
}
