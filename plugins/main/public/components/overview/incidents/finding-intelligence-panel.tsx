import React, { useState } from 'react';
import { EuiBasicTable, EuiBasicTableColumn, EuiButtonEmpty, EuiSpacer, EuiText, EuiTitle } from '@elastic/eui';
import type { FindingObservation } from '../../../../common/incidents/contracts';
import { summarizeFindings } from './finding-intelligence-model';

type EntityRow = ReturnType<typeof summarizeFindings>['entities'][number];

export function FindingIntelligencePanel({ observations }: { observations: FindingObservation[] }) {
  const { entities, techniques, tactics, ordered } = summarizeFindings(observations);
  const [expanded, setExpanded] = useState(false);
  const entityColumns: Array<EuiBasicTableColumn<EntityRow>> = [
    { field: 'kind', name: 'Type', render: (value: string) => value.replace(/_/g, ' ') },
    { field: 'value', name: 'Entity' },
    { field: 'count', name: 'Findings on page' },
    { field: 'fields', name: 'Source fields', render: (fields: string[]) => fields.join(', ') },
  ];
  const timelineColumns: Array<EuiBasicTableColumn<FindingObservation>> = [
    { field: 'timestamp', name: 'Finding time (UTC)', render: (value: string | null) => value ?? 'Unknown' },
    { field: 'rule_title', name: 'Detection', render: (value: string | null) => value ?? 'Not available' },
    { field: 'rule_id', name: 'Rule ID' },
    { field: 'document_id', name: 'Finding reference' },
  ];
  return <>
    <EuiTitle size='s'><h2>Finding intelligence</h2></EuiTitle>
    <EuiText size='s'>Live observations from visible findings on this page only. Missing fields, hidden findings and expired sources are not inferred. Entity matches are not proof of shared identity.</EuiText>
    <EuiSpacer size='s' />
    <EuiTitle size='xs'><h3>Entities ({entities.length})</h3></EuiTitle>
    <EuiBasicTable<EntityRow> items={expanded ? entities : entities.slice(0, 20)} columns={entityColumns} noItemsMessage='No visible entities' />
    {entities.length > 20 && <EuiButtonEmpty onClick={() => setExpanded(value => !value)}>{expanded ? 'Show fewer entities' : 'Show all entities on this page'}</EuiButtonEmpty>}
    <EuiSpacer size='s' />
    <EuiTitle size='xs'><h3>MITRE ATT&CK</h3></EuiTitle>
    <EuiText size='s'><p>Techniques: {techniques.length ? techniques.join(', ') : 'Not available'}</p><p>Tactics: {tactics.length ? tactics.join(', ') : 'Not available'}</p></EuiText>
    <EuiSpacer size='s' />
    <EuiTitle size='xs'><h3>Finding timeline (this page)</h3></EuiTitle>
    <EuiBasicTable<FindingObservation> items={ordered} columns={timelineColumns} noItemsMessage='No visible finding observations' />
  </>;
}
