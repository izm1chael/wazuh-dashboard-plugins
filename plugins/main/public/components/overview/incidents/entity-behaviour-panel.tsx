import React, { useEffect, useRef, useState } from 'react';
import { EuiBasicTable, EuiBasicTableColumn, EuiButton, EuiButtonEmpty, EuiCallOut, EuiFieldText, EuiFormRow, EuiPanel, EuiSelect, EuiSpacer, EuiText, EuiTextArea, EuiTitle } from '@elastic/eui';
import { BEHAVIOUR_FIELDS, BehaviourField, BehaviourReport, BehaviourAssessment, validateBehaviourInput, validateBehaviourReport } from '../../../../common/incidents/behaviour-contract';
import type { HuntInput, HuntRow } from '../../../../common/incidents/hunt-contract';
import { getHttp } from '../../../kibana-services';
import { IncidentHuntPanel } from './incident-hunt-panel';

const DAY=86400000;
const lastDay=()=>new Date(Math.floor((Date.now()-120000)/DAY)*DAY-DAY).toISOString().slice(0,10);
const labels={no_observed_activity:'No observed activity',newly_observed:'Newly observed in comparison window',
  sparse_baseline:'Sparse baseline — insufficient history',elevated_volume:'Elevated finding volume',within_volume_threshold:'Within volume threshold'};

export function EntityBehaviourPanel({back,openRelated}: {back:()=>void;openRelated?:(id:string)=>void}) {
  const [field,setField]=useState<BehaviourField>('user.name');
  const [values,setValues]=useState('');
  const [day,setDay]=useState(lastDay);
  const [report,setReport]=useState<BehaviourReport>();
  const [selected,setSelected]=useState('');
  const [pivot,setPivot]=useState(false);
  const [busy,setBusy]=useState(false);
  const [error,setError]=useState(false);
  const active=useRef(false),generation=useRef(0);
  useEffect(()=>()=>{generation.current++;},[]);
  const reset=()=>{setReport(undefined);setSelected('');setPivot(false);setError(false);};
  let input:HuntInput|undefined;
  try{
    if(!/^\d{4}-\d{2}-\d{2}$/.test(day))throw new Error('Invalid day');
    const from=new Date(day+'T00:00:00Z').toISOString();
    if(from.slice(0,10)!==day)throw new Error('Invalid day');
    input=validateBehaviourInput({field,values:values.split(/\r?\n/).filter(v=>v.length>0),from,until:new Date(Date.parse(from)+DAY).toISOString()});
  }catch(_){/* invalid input */}
  async function run(){
    if(!input||active.current)return;
    const request=input,seq=++generation.current;
    active.current=true;setBusy(true);reset();
    try{
      const result=validateBehaviourReport(await getHttp().post<BehaviourReport>('/indexer/incident-behaviour/assess',{body:JSON.stringify(request)}),request);
      if(seq===generation.current){setReport(result);setSelected(result.assessments[0].value);}
    }catch(_){if(seq===generation.current)setError(true);}
    finally{active.current=false;if(seq===generation.current)setBusy(false);}
  }
  const columns:Array<EuiBasicTableColumn<BehaviourAssessment>>=[
    {field:'value',name:'Exact entity value'},{field:'baseline_total',name:'7-day findings'},
    {field:'active_days',name:'Active days'},{field:'baseline_maximum',name:'Daily maximum'},
    {field:'threshold',name:'Volume threshold'},{field:'current_count',name:'Comparison findings'},
    {name:'Observation',render:row=>labels[row.classification]}
  ];
  const detail=report?.assessments.find(row=>row.value===selected);
  const historyColumns:Array<EuiBasicTableColumn<HuntRow>>=[{field:'timestamp',name:'Observed (UTC)'},{field:'index',name:'Finding index'},{field:'document_id',name:'Finding ID'}];
  const counts=detail?[...detail.daily_counts,detail.current_count]:[];
  const max=Math.max(1,...counts);
  return <>
    <EuiButtonEmpty onClick={back}>Back to incidents</EuiButtonEmpty>
    <EuiTitle size='l'><h1>Entity behaviour analytics</h1></EuiTitle>
    <EuiCallOut title='Experimental finding-volume comparison'>Read-only, deterministic comparison of seven UTC baseline days with one completed UTC day. This is not authentication event analytics, a calibrated risk score or proof of compromise. Missing retention, telemetry, rule changes and access changes may affect counts. A zero result does not prove inactivity. No incidents or responses are automatically created.</EuiCallOut>
    <EuiSpacer size='m'/>
    <EuiFormRow label='Exact entity field'><EuiSelect value={field} disabled={busy} options={BEHAVIOUR_FIELDS.map(v=>({value:v,text:v}))}
      onChange={e=>{reset();setField(e.target.value as BehaviourField);}}/></EuiFormRow>
    <EuiFormRow label='One to five exact values, one per line'><EuiTextArea value={values} maxLength={1285} disabled={busy}
      onChange={e=>{reset();setValues(e.target.value);}}/></EuiFormRow>
    <EuiFormRow label='Completed UTC comparison day (YYYY-MM-DD)' helpText='Seven preceding days form the baseline; the selected day must end at least two minutes ago.'>
      <EuiFieldText value={day} maxLength={10} disabled={busy} onChange={e=>{reset();setDay(e.target.value);}}/>
    </EuiFormRow>
    <EuiButton disabled={!input||busy} isLoading={busy} onClick={()=>void run()}>Compare finding volume</EuiButton>
    {error&&<EuiCallOut color='warning' title='Assessment unavailable'>Check permission, field mapping and scope. Both searches must return complete exact results with at most 100 distinct findings each. No partial results or fabricated zero counts are displayed.</EuiCallOut>}
    {report&&<>
      <EuiSpacer size='m'/>
      <EuiText size='s'>Baseline {report.baseline.from} to {report.baseline.until}: {report.baseline.match_count} distinct findings. Comparison {report.current.from} to {report.current.until}: {report.current.match_count} distinct findings. Searches are separate current observations, not an atomic or ingestion-complete snapshot.</EuiText>
      <EuiBasicTable<BehaviourAssessment> items={report.assessments} columns={columns} itemId='value'/>
      <EuiText size='s'>Threshold = maximum of 5, baseline daily maximum + 3, and twice baseline daily mean rounded up. Elevated volume requires at least three baseline days with observed findings. Sparse and newly observed results are not ranked as risk.</EuiText>
      <EuiFormRow label='Inspect exact entity'><EuiSelect value={selected} options={report.assessments.map(row=>({value:row.value,text:row.value}))}
        onChange={e=>{setSelected(e.target.value);setPivot(false);}}/></EuiFormRow>
      {detail&&<EuiPanel hasBorder hasShadow={false}>
        <EuiTitle size='s'><h2>{labels[detail.classification]}</h2></EuiTitle>
        <div style={{display:'flex',gap:8,alignItems:'end',height:104}} role='img' aria-label='Seven baseline daily counts and comparison day'>
          {counts.map((count,n)=><div key={n} title={String(count)} style={{flex:1,height:Math.max(2,Math.round(100*count/max)),background:'currentColor',opacity:n===7?0.85:0.35}}/>)}
        </div>
        <EuiText size='s'>Baseline daily counts (oldest first): {detail.daily_counts.join(', ')}. Comparison day: {detail.current_count}.</EuiText>
        <EuiTitle size='xs'><h3>Comparison finding references</h3></EuiTitle>
        <EuiBasicTable<HuntRow> items={report.current.rows.filter(row=>row.matched_values.includes(selected))} columns={historyColumns} noItemsMessage='No exact matches'/>
        <details><summary>Baseline finding references</summary>
          <EuiBasicTable<HuntRow> items={report.baseline.rows.filter(row=>row.matched_values.includes(selected))} columns={historyColumns} noItemsMessage='No exact matches'/>
        </details>
        <EuiButtonEmpty onClick={()=>setPivot(v=>!v)}>{pivot?'Close investigation pivot':'Prepare related-case investigation'}</EuiButtonEmpty>
        {pivot&&<IncidentHuntPanel key={selected} initial={{field:report.current.field,value:selected,from:report.current.from,until:report.current.until}} openRelated={openRelated}/>}
      </EuiPanel>}
    </>}
  </>;
}
