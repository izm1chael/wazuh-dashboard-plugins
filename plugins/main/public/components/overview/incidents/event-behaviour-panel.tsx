import React, { useEffect, useRef, useState } from 'react';
import { EuiButton, EuiButtonEmpty, EuiCallOut, EuiFieldText, EuiFormRow, EuiSelect, EuiSpacer, EuiText, EuiTitle } from '@elastic/eui';
import { EventMode, EVENT_MODES, EventProfile, EventProfileInput, EventRelationships, validateEventProfileInput, validateEventProfile } from '../../../../common/incidents/event-behaviour-contract';
import type { RuleVolumeAssessment } from '../../../../common/incidents/rule-behaviour-contract';
import { getHttp } from '../../../kibana-services';
const DAY=86400000;
function Volume({name,row}:{name:string;row:RuleVolumeAssessment}){
  return <EuiText size='s'><strong>{name}</strong>: comparison {row.current_count}; baseline {row.baseline_total}; threshold {row.threshold}; {row.classification.replace(/_/g,' ')}.
    <details><summary>Daily baseline counts</summary>{row.daily_counts.join(', ')}</details></EuiText>;
}
function Relations({name,row}:{name:string;row:EventRelationships}){
  return <EuiText size='s'><h3>{name}</h3><p>Distinct baseline {row.baseline_distinct}; comparison {row.comparison_distinct}; missing baseline {row.baseline_missing}; missing comparison {row.comparison_missing}.</p>
    <p>Newly observed in this retained window, not first-ever:</p><ul>{row.newly_observed.map(item=><li key={item.value}>{item.value}: {item.count}</li>)}</ul></EuiText>;
}
export function EventBehaviourPanel({back}:{back:()=>void}){
  const [mode,setMode]=useState<EventMode>('authentication');
  const [cluster,setCluster]=useState(''),[space,setSpace]=useState(''),[dataset,setDataset]=useState(''),[subject,setSubject]=useState('');
  const [day,setDay]=useState(()=>new Date(Math.floor((Date.now()-120000)/DAY)*DAY-DAY).toISOString().slice(0,10));
  const [report,setReport]=useState<EventProfile>(),[busy,setBusy]=useState(false),[error,setError]=useState(false);
  const generation=useRef(0),active=useRef(false);
  useEffect(()=>()=>{generation.current++;},[]);
  const reset=()=>{setReport(undefined);setError(false);};
  let input:EventProfileInput|undefined;
  try{input=validateEventProfileInput({mode,cluster,space,dataset,subject,day:day+'T00:00:00Z'});}catch(_){/* invalid form */}
  async function run(){
    if(!input||active.current)return;
    const query=input,seq=++generation.current;active.current=true;setBusy(true);reset();
    try{
      const response=validateEventProfile(await getHttp().post<EventProfile>('/indexer/incident-behaviour/event-assess',{body:JSON.stringify(query)}),query);
      if(seq===generation.current)setReport(response);
    }catch(_){if(seq===generation.current)setError(true);}
    finally{active.current=false;if(seq===generation.current)setBusy(false);}
  }
  return <>
    <EuiButtonEmpty onClick={back}>Back to incidents</EuiButtonEmpty>
    <EuiTitle size='l'><h1>Native event behaviour profiles</h1></EuiTitle>
    <EuiCallOut title='Experimental normalized-event analytics'>Requires an exact decoder dataset, cluster and space. Counts event documents, not unique login sessions or processes. Unknown outcomes and missing relationships are explicit. Search completeness is not telemetry completeness. No automatic incident, risk score or response.</EuiCallOut>
    <EuiSpacer size='m'/>
    <EuiFormRow label='Profile'><EuiSelect value={mode} options={EVENT_MODES.map(v=>({value:v,text:v}))} disabled={busy} onChange={e=>{reset();setMode(e.target.value as EventMode);setSubject('');}}/></EuiFormRow>
    {([{name:'Cluster',v:cluster,set:setCluster},{name:'Space',v:space,set:setSpace},{name:'Event dataset',v:dataset,set:setDataset},
      {name:mode==='authentication'?'Exact user.id':'Exact host.id',v:subject,set:setSubject},{name:'Comparison day (UTC YYYY-MM-DD)',v:day,set:setDay}]).map(item=>
      <EuiFormRow key={item.name} label={item.name}><EuiFieldText value={item.v} disabled={busy} maxLength={item.name.startsWith('Comparison')?10:256}
        onChange={e=>{reset();item.set(e.target.value);}}/></EuiFormRow>)}
    <EuiButton disabled={!input||busy} isLoading={busy} onClick={()=>void run()}>Assess native events</EuiButton>
    {error&&<EuiCallOut color='warning' title='Profile unavailable'>Check source access, decoder mapping and scope. Incomplete, ambiguous or over-cap results are rejected.</EuiCallOut>}
    {report&&<>
      <EuiSpacer size='m'/><EuiText size='s'>Observed {report.observed_at}; {report.event_count} matching event documents across 29 days.</EuiText>
      <Volume name='All selected events' row={report.volume}/>
      {report.authentication&&<><Volume name='Authentication success' row={report.authentication.success}/><Volume name='Authentication failure' row={report.authentication.failure}/><Volume name='Unknown outcome' row={report.authentication.unknown}/></>}
      <Relations name={mode==='authentication'?'User-to-host ID':mode==='process'?'Host-to-executable':'Host-to-destination IPv4'} row={report.relationship}/>
      {report.source_relationship&&<Relations name='User-to-source IPv4' row={report.source_relationship}/>}
      <EuiTitle size='s'><h2>Observed ingestion coverage</h2></EuiTitle>
      <EuiText size='s'>Active baseline days {report.coverage.active_baseline_days}/28. Valid event ingestion timestamps {report.coverage.ingest_lag_known}; missing {report.coverage.ingest_lag_missing}; before event {report.coverage.ingest_before_event}; after observation {report.coverage.ingest_after_observation}. Lag over 120 seconds {report.coverage.lag_over_120s}; maximum valid lag {report.coverage.max_lag_seconds}s. This is not an ingestion watermark or evidence that absent events did not occur.</EuiText>
    </>}
  </>;
}
