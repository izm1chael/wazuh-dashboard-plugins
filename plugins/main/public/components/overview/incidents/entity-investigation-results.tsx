import React, { useState } from 'react';
import { EuiBasicTable, EuiBasicTableColumn, EuiButtonEmpty, EuiFlexGroup, EuiFlexItem, EuiFormRow, EuiPanel, EuiSelect, EuiSpacer, EuiText, EuiTitle } from '@elastic/eui';
import { EntityInvestigation, RelatedIncident, entityTimeline, investigationGraph, findingKey } from '../../../../common/incidents/entity-investigation';

export function EntityInvestigationResults({ report, disabled, openRelated }: {
  report: EntityInvestigation; disabled: boolean; openRelated?: (id: string) => void;
}) {
  const [value, setValue] = useState('');
  const [selected, setSelected] = useState('');
  const filter = value || undefined;
  const buckets = entityTimeline(report.hunt, filter);
  const graph = investigationGraph(report, filter);
  const findings = report.hunt.rows.filter(row => !filter || row.matched_values.includes(filter));
  const visible = new Set(findings.map(findingKey));
  const cases = report.cases.filter(row => row.matches.some(ref => visible.has(findingKey(ref))));
  const current = findings.find(row => findingKey(row) === selected);
  const node = current ? 'finding:' + findingKey(current) : '';
  const upstream = new Set(graph.edges.filter(edge => edge.to === node).map(edge => edge.from));
  const downstream = new Set(graph.edges.filter(edge => edge.from === node).map(edge => edge.to));
  const max = Math.max(1, ...buckets.map(bucket => bucket.count));
  const columns: Array<EuiBasicTableColumn<RelatedIncident>> = [
    { field: 'id', name: 'Incident ID' }, { field: 'revision', name: 'Observed revision' },
    { field: 'status', name: 'Status' }, { field: 'severity', name: 'Severity' },
    { name: 'Matching findings', render: row => row.matches.filter(ref => visible.has(findingKey(ref))).length },
  ];
  if (openRelated) columns.push({ name: 'Action', render: row => <EuiButtonEmpty disabled={disabled}
    onClick={() => openRelated(row.id)}>Open incident</EuiButtonEmpty> });
  return <>
    <EuiTitle size='s'><h2>Entity activity and related incidents</h2></EuiTitle>
    <EuiText size='s'>These are exact matches in the retained, caller-visible finding snapshot and current shared-SOC case links. Matching links do not prove common actors, causality, compromise or duplicate incidents. Case and finding searches are separate observations, not an atomic snapshot.</EuiText>
    <EuiSpacer size='s' />
    <EuiFormRow label='Filter to exact observed value'><EuiSelect value={value} disabled={disabled}
      options={[{value:'',text:'All selected values'},...report.hunt.values.map(v=>({value:v,text:v}))]}
      onChange={e=>{setValue(e.target.value);setSelected('');}} /></EuiFormRow>
    <EuiText size='s'>{findings.length} distinct findings · {cases.length} linked incidents · {graph.edges.length} exact evidence edges</EuiText>
    <EuiTitle size='xs'><h3>Activity timeline (UTC)</h3></EuiTitle>
    <EuiText size='xs'>Distinct findings per half-open time bucket. A finding matching multiple selected values is counted once.</EuiText>
    <EuiPanel hasBorder hasShadow={false} paddingSize='s'>
      <div style={{display:'flex',alignItems:'end',height:96,gap:3}} role='img' aria-label='Finding count by time bucket; detailed counts follow'>
        {buckets.map(bucket=><div key={bucket.from} title={bucket.from+' – '+bucket.until+': '+bucket.count}
          style={{flex:1,height:Math.max(1,Math.round(bucket.count/max*90)),backgroundColor:'currentColor',opacity:bucket.count?0.65:0.15}} />)}
      </div>
      <EuiText size='xs'>{buckets[0]?.from} to {buckets[buckets.length-1]?.until}</EuiText>
      <details><summary>Exact bucket counts</summary>
        <EuiText size='xs'><table><thead><tr><th>From (inclusive)</th><th>Until (exclusive)</th><th>Findings</th></tr></thead>
          <tbody>{buckets.map(bucket=><tr key={bucket.from}><td>{bucket.from}</td><td>{bucket.until}</td><td>{bucket.count}</td></tr>)}</tbody></table></EuiText>
      </details>
    </EuiPanel>
    <EuiSpacer size='m' />
    <EuiTitle size='xs'><h3>Related incident candidates</h3></EuiTitle>
    <EuiBasicTable<RelatedIncident> items={cases} columns={columns} itemId='id' noItemsMessage='No exact case links in this investigation' />
    <EuiSpacer size='m' />
    <EuiTitle size='xs'><h3>Evidence relationship explorer</h3></EuiTitle>
    <EuiText size='s'>Select a finding to inspect its observed exact-value edges and linked case edges. No inferred relationships are generated.</EuiText>
    <EuiFormRow label='Finding'><EuiSelect value={selected} disabled={disabled} options={[{value:'',text:'Choose a finding'},
      ...findings.map(row=>({value:findingKey(row),text:row.timestamp+' · '+row.index+' / '+row.document_id}))]}
      onChange={e=>setSelected(e.target.value)} /></EuiFormRow>
    {current && <EuiFlexGroup direction='row' wrap>
      <EuiFlexItem><EuiPanel hasBorder hasShadow={false}><EuiText size='s'><strong>Exact matched values</strong>
        <ul>{graph.nodes.filter(n=>upstream.has(n.id)).map(n=><li key={n.id} style={{overflowWrap:'anywhere'}}>{n.label}</li>)}</ul></EuiText></EuiPanel></EuiFlexItem>
      <EuiFlexItem><EuiPanel hasBorder hasShadow={false}><EuiText size='s'><strong>Finding</strong>
        <p style={{overflowWrap:'anywhere'}}>{current.index} / {current.document_id}</p><p>{current.timestamp}</p></EuiText></EuiPanel></EuiFlexItem>
      <EuiFlexItem><EuiPanel hasBorder hasShadow={false}><EuiText size='s'><strong>Linked incidents</strong>
        {downstream.size===0 ? <p>No exact case links</p> : <ul>{graph.nodes.filter(n=>downstream.has(n.id)).map(n=><li key={n.id}>
          {openRelated ? <EuiButtonEmpty disabled={disabled} onClick={()=>openRelated(n.label)}>{n.label}</EuiButtonEmpty> : n.label}
        </li>)}</ul>}</EuiText></EuiPanel></EuiFlexItem>
    </EuiFlexGroup>}
  </>;
}
