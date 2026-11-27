import React, { useEffect, useRef, useState } from 'react';
import { EuiButton, EuiButtonEmpty, EuiCallOut, EuiFieldText, EuiFormRow, EuiPanel, EuiSelect, EuiSpacer, EuiText, EuiTitle } from '@elastic/eui';
import { BEHAVIOUR_FIELDS, BehaviourField } from '../../../../common/incidents/behaviour-contract';
import { RuleBehaviourInput, RuleBehaviourReport, validateRuleBehaviour, validateRuleBehaviourReport } from '../../../../common/incidents/rule-behaviour-contract';
import { getHttp } from '../../../kibana-services';
import { IncidentHuntPanel } from './incident-hunt-panel';

const DAY=86400000;
const labels={no_observed_activity:'No observed matches',newly_observed:'Newly observed in this window',
  sparse_baseline:'Sparse baseline',elevated_rule_volume:'Elevated rule finding volume',within_volume_threshold:'Within volume threshold'};
export function RuleBehaviourPanel({back,openRelated}: {back:()=>void;openRelated?:(id:string)=>void}){
  const [field,setField]=useState<BehaviourField>('user.name');
  const [value,setValue]=useState('');
  const [rule,setRule]=useState('');
  const [day,setDay]=useState(()=>new Date(Math.floor((Date.now()-120000)/DAY)*DAY-DAY).toISOString().slice(0,10));
  const [report,setReport]=useState<RuleBehaviourReport>();
  const [busy,setBusy]=useState(false),[error,setError]=useState(false),[pivot,setPivot]=useState(false);
  const active=useRef(false),generation=useRef(0);
  useEffect(()=>()=>{generation.current++;},[]);
  const reset=()=>{setReport(undefined);setError(false);setPivot(false);};
  let query:RuleBehaviourInput|undefined;
  try{query=validateRuleBehaviour({field,value,rule_uuid:rule,day:day+'T00:00:00Z'});}catch(_){/* invalid form */}
  async function run(){
    if(!query||active.current)return;
    const input=query,seq=++generation.current;
    active.current=true;setBusy(true);reset();
    try{
      const body=validateRuleBehaviourReport(await getHttp().post<RuleBehaviourReport>('/indexer/incident-behaviour/rule-assess',{body:JSON.stringify(input)}),input);
      if(seq===generation.current)setReport(body);
    }catch(_){if(seq===generation.current)setError(true);}
    finally{active.current=false;if(seq===generation.current)setBusy(false);}
  }
  const a=report?.assessment,counts=a?[...a.daily_counts,a.current_count]:[],max=Math.max(1,...counts);
  return <>
    <EuiButtonEmpty onClick={back}>Back to incidents</EuiButtonEmpty>
    <EuiTitle size='l'><h1>Rule-specific behaviour analytics</h1></EuiTitle>
    <EuiCallOut title='Experimental 28-day rule volume comparison'>One exact entity and detection rule. Up to 2,000 matching findings, one completed UTC day against 28 prior days. This measures detection activity, not authentication success, attack probability or calibrated entity risk. Search completeness does not establish telemetry completeness.</EuiCallOut>
    <EuiSpacer size='m'/>
    <EuiFormRow label='Entity field'><EuiSelect value={field} disabled={busy} options={BEHAVIOUR_FIELDS.map(v=>({value:v,text:v}))}
      onChange={e=>{reset();setField(e.target.value as BehaviourField);}}/></EuiFormRow>
    <EuiFormRow label='Exact entity value'><EuiFieldText value={value} maxLength={256} disabled={busy} onChange={e=>{reset();setValue(e.target.value);}}/></EuiFormRow>
    <EuiFormRow label='Exact detection rule UUID'><EuiFieldText value={rule} maxLength={36} disabled={busy} onChange={e=>{reset();setRule(e.target.value);}}/></EuiFormRow>
    <EuiFormRow label='Completed comparison day (YYYY-MM-DD)'><EuiFieldText value={day} maxLength={10} disabled={busy} onChange={e=>{reset();setDay(e.target.value);}}/></EuiFormRow>
    <EuiButton disabled={!query||busy} isLoading={busy} onClick={()=>void run()}>Assess rule-specific behaviour</EuiButton>
    {error&&<EuiCallOut color='warning' title='Assessment unavailable'>Check access, field mapping and rule UUID, or use a lower-volume scope. Incomplete or over-cap searches are not scored.</EuiCallOut>}
    {report&&a&&<>
      <EuiSpacer size='m'/>
      <EuiPanel hasBorder hasShadow={false}>
        <EuiTitle size='s'><h2>{labels[a.classification]}</h2></EuiTitle>
        <EuiText size='s'><p>Rule {report.query.rule_uuid} · {report.query.field}: {report.query.value}</p>
          <p>Baseline total {a.baseline_total}; active baseline days {a.active_days}/28; comparison {a.current_count}; threshold {a.threshold}.</p>
          <p>Same-weekday maximum {a.same_weekday_maximum}; baseline median {a.median_times_two/2}; median absolute deviation {a.mad_times_four/4}.</p>
          <p>Threshold is the maximum of 5, same-weekday maximum + 3, twice baseline mean rounded up, and median + 3 MAD rounded up. At least seven active baseline days are required for an elevated classification.</p>
        </EuiText>
        <div style={{display:'flex',gap:3,alignItems:'end',height:100}} role='img' aria-label='28 baseline daily counts and comparison day'>
          {counts.map((n,i)=><div key={i} title={new Date(Date.parse(report.baseline_from)+i*DAY).toISOString().slice(0,10)+': '+n}
            style={{flex:1,height:Math.max(2,Math.round(96*n/max)),background:'currentColor',opacity:i===28?0.85:0.35}}/>)}
        </div>
        <details><summary>Exact daily counts</summary><EuiText size='s'><ol>{counts.map((n,i)=><li key={i}>{new Date(Date.parse(report.baseline_from)+i*DAY).toISOString().slice(0,10)}: {n}</li>)}</ol></EuiText></details>
        <EuiText size='s'><p>Search completed at {report.observed_at} under {report.actor}. Telemetry and ingestion coverage unverified.</p>
          <p>Comparison sample: {report.current_sample.length} of {a.current_count} matching findings, earliest first. Not a complete evidence export.</p>
          <ul>{report.current_sample.map(row=><li key={JSON.stringify([row.index,row.document_id])}>{row.timestamp} · {row.index} / {row.document_id}</li>)}</ul>
        </EuiText>
        <EuiButtonEmpty onClick={()=>setPivot(v=>!v)}>{pivot?'Close pivot':'Prepare broader entity investigation'}</EuiButtonEmpty>
        {pivot&&<><EuiText size='s'>This pivot searches the selected entity during the comparison day without restricting the rule. Review and execute explicitly.</EuiText>
          <IncidentHuntPanel initial={{field:report.query.field,value:report.query.value,from:report.query.day,until:report.until}} openRelated={openRelated}/></>}
      </EuiPanel>
    </>}
  </>;
}
