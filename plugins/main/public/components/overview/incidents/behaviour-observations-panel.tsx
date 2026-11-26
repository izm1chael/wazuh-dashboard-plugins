import React, { useEffect, useRef, useState } from 'react';
import { EuiBasicTable, EuiBasicTableColumn, EuiButton, EuiButtonEmpty, EuiCallOut, EuiFieldText, EuiFormRow, EuiPanel, EuiSelect, EuiSpacer, EuiText, EuiTextArea, EuiTitle } from '@elastic/eui';
import { BehaviourObservation, ObservationPage, ObservationDecision, EntityObservationPriority, entityObservationPriorities, OBSERVATION_DECISIONS, validateObservationDay, validateObservationPage, validateObservationReview, validateReviewResult, validatePromotionResult } from '../../../../common/incidents/behaviour-observation-contract';
import { getHttp } from '../../../kibana-services';
import { IncidentHuntPanel } from './incident-hunt-panel';

const DAY=86400000,ROOT='/indexer/incident-behaviour/observations';
const label=(s:string)=>s.replace(/_/g,' ');
export function BehaviourObservationsPanel({back,openRelated}: {back:()=>void;openRelated:(id:string)=>void}){
  const [day,setDay]=useState(()=>new Date(Math.floor((Date.now()-120000)/DAY)*DAY-DAY).toISOString().slice(0,10));
  const [page,setPage]=useState<ObservationPage>();
  const [selected,setSelected]=useState('');
  const [decision,setDecision]=useState<ObservationDecision>('monitor');
  const [reason,setReason]=useState('');
  const [confirm,setConfirm]=useState(false);
  const [pivot,setPivot]=useState(false);
  const [busy,setBusy]=useState(false);
  const [error,setError]=useState('');
  const generation=useRef(0),active=useRef(false);
  useEffect(()=>()=>{generation.current++;},[]);
  const resetSelection=()=>{setSelected('');setReason('');setConfirm(false);setPivot(false);};
  const reset=()=>{setPage(undefined);resetSelection();setError('');};
  let requestedDay:string|undefined;
  try{requestedDay=validateObservationDay(day+'T00:00:00Z');}catch(_){/* invalid date */}
  const row=page?.rows.find(r=>r.id===selected);
  async function load(){
    if(!requestedDay||active.current)return;
    const date=requestedDay,seq=++generation.current;
    active.current=true;setBusy(true);reset();
    try{
      const result=validateObservationPage(await getHttp().post<ObservationPage>(ROOT+'/day',{body:JSON.stringify({day:date})}),date);
      if(generation.current===seq)setPage(result);
    }catch(_){if(generation.current===seq)setError('Observation queue unavailable or incomplete. Check permissions, feature configuration and the 50-record daily limit.');}
    finally{active.current=false;if(generation.current===seq)setBusy(false);}
  }
  let reviewInput:ReturnType<typeof validateObservationReview>|undefined;
  try{if(row?.state==='unreviewed')reviewInput=validateObservationReview({id:row.id,expected_revision:row.revision,decision,reason});}catch(_){/* invalid review */}
  async function mutate(promote:boolean){
    if(active.current||!row||!page||!confirm||(!promote&&!reviewInput))return;
    if(promote&&row.state!=='escalation_requested')return;
    const seq=++generation.current,input={id:row.id,expected_revision:row.revision},date=page.day;
    active.current=true;setBusy(true);setConfirm(false);setError('');
    try{
      if(promote)validatePromotionResult(await getHttp().post<BehaviourObservation>(ROOT+'/promote',{body:JSON.stringify(input)}),input);
      else if(reviewInput)validateReviewResult(await getHttp().post<BehaviourObservation>(ROOT+'/review',{body:JSON.stringify(reviewInput)}),reviewInput);
      const result=validateObservationPage(await getHttp().post<ObservationPage>(ROOT+'/day',{body:JSON.stringify({day:date})}),date);
      if(generation.current===seq){setPage(result);setReason('');setPivot(false);}
    }catch(_){if(generation.current===seq){setPage(undefined);resetSelection();setError('Operation or refresh incomplete. Reload before retrying. A case may already exist after a promotion failure; the same reviewer can retry the idempotent promotion after reload.');}}
    finally{active.current=false;if(generation.current===seq)setBusy(false);}
  }
  const columns:Array<EuiBasicTableColumn<BehaviourObservation>>=[
    {name:'Entity',render:r=>r.query.field+': '+r.query.value},
    {name:'Rule UUID',render:r=>r.query.rule_uuid},
    {name:'Observation',render:r=>label(r.assessment.classification)},
    {name:'Findings / threshold',render:r=>r.assessment.current_count+' / '+r.assessment.threshold},
    {name:'Review state',render:r=>label(r.state)},
    {name:'Action',render:r=><EuiButtonEmpty disabled={busy} onClick={()=>{resetSelection();setSelected(r.id);}}>Inspect</EuiButtonEmpty>}
  ];
  const priorityColumns:Array<EuiBasicTableColumn<EntityObservationPriority>>=[
    {name:'Exact entity',render:r=>r.field+': '+r.value},
    {field:'publisher',name:'Publisher'},
    {field:'observed_rules',name:'Observed rules'},
    {field:'elevated_rules',name:'Elevated'},
    {field:'newly_observed_rules',name:'Novelty'},
    {field:'awaiting_review',name:'Awaiting review'},
    {field:'awaiting_promotion',name:'Awaiting promotion'},
  ];
  return <>
    <EuiButtonEmpty onClick={back}>Back to incidents</EuiButtonEmpty>
    <EuiTitle size='l'><h1>Behaviour observation review</h1></EuiTitle>
    <EuiCallOut title='Shared SOC metadata'>These are published, bounded rule-volume observations, not confirmed threats. Approved publishers share entity values and counts with all observation readers. Telemetry completeness is unverified. No raw finding references are stored. Elevated volume is listed before novelty, not ranked by compromise probability.</EuiCallOut>
    <EuiSpacer size='m'/>
    <EuiFormRow label='Completed comparison day (YYYY-MM-DD)'><EuiFieldText value={day} maxLength={10} disabled={busy} onChange={e=>{reset();setDay(e.target.value);}}/></EuiFormRow>
    <EuiButton disabled={!requestedDay||busy} isLoading={busy} onClick={()=>void load()}>Load daily observations</EuiButton>
    {error&&<EuiCallOut title='Review unavailable' color='warning'>{error}</EuiCallOut>}
    {page&&<>
      <EuiText size='s'>{page.count} recorded observations; {page.rows.filter(r=>r.state==='unreviewed').length} awaiting review; {page.rows.filter(r=>r.state==='escalation_requested').length} awaiting promotion. A missing record does not prove a policy ran or activity was absent.</EuiText>
      <EuiTitle size='s'><h2>Entity review prioritisation</h2></EuiTitle>
      <EuiText size='s'>Grouped by exact publisher, field and literal. Counts distinct rule observations, not distinct attacks or summed findings. Sorted by outstanding analyst work and flagged rules; not a risk score.</EuiText>
      <EuiBasicTable<EntityObservationPriority> items={entityObservationPriorities(page)} columns={priorityColumns} itemId='key' noItemsMessage='No recorded entities'/>
      <EuiSpacer size='m'/>
      <EuiTitle size='s'><h2>Individual observations</h2></EuiTitle>
      <EuiBasicTable<BehaviourObservation> items={page.rows} columns={columns} itemId='id' noItemsMessage='No observations recorded for this day'/>
    </>}
    {row&&<EuiPanel hasBorder hasShadow={false}>
      <EuiTitle size='s'><h2>{label(row.state)} · {row.id}</h2></EuiTitle>
      <EuiText size='s'><p>Published by {row.actor} at {row.observed_at}; revision {row.revision}.</p>
        <p>{row.query.field}: {row.query.value} · rule {row.query.rule_uuid}</p>
        <p>{label(row.assessment.classification)}: comparison {row.assessment.current_count}, threshold {row.assessment.threshold}, baseline total {row.assessment.baseline_total}, active days {row.assessment.active_days}/28.</p>
        <p>Daily baseline counts: {row.assessment.daily_counts.join(', ')}.</p>
        {row.review&&<p>Reviewed by {row.review.actor} at {row.review.at}: {label(row.review.decision)} — {row.review.reason}</p>}
        {row.promoted_at&&<p>Promotion recorded at {row.promoted_at}.</p>}
      </EuiText>
      <EuiButtonEmpty disabled={busy} onClick={()=>setPivot(v=>!v)}>{pivot?'Close investigation':'Prepare broader entity investigation'}</EuiButtonEmpty>
      {pivot&&<IncidentHuntPanel key={row.id} initial={{field:row.query.field,value:row.query.value,from:row.query.day,until:new Date(Date.parse(row.query.day)+DAY).toISOString()}} disabled={busy} openRelated={openRelated}/>}
      {row.state==='unreviewed'&&<>
        <EuiFormRow label='Independent review decision'><EuiSelect value={decision} disabled={busy} options={OBSERVATION_DECISIONS.map(v=>({value:v,text:label(v)}))} onChange={e=>{setDecision(e.target.value as ObservationDecision);setConfirm(false);}}/></EuiFormRow>
        <EuiFormRow label='Reason (no restricted evidence or secrets)'><EuiTextArea value={reason} maxLength={1024} disabled={busy} onChange={e=>{setReason(e.target.value);setConfirm(false);}}/></EuiFormRow>
        <label><input type='checkbox' disabled={busy} checked={confirm} onChange={e=>setConfirm(e.target.checked)}/> Confirm permanent review decision. Publisher cannot review their own observation.</label>
        <EuiButton disabled={busy||!confirm||!reviewInput} onClick={()=>void mutate(false)}>Record review</EuiButton>
      </>}
      {row.state==='escalation_requested'&&<>
        <EuiText size='s'>Only the recorded reviewer with promotion permission may create the informational incident. No evidence is automatically attached. The incident references this observation ID, and uses the existing idempotent creation path.</EuiText>
        <label><input type='checkbox' checked={confirm} disabled={busy} onChange={e=>setConfirm(e.target.checked)}/> Confirm creation of an informational incident for investigation.</label>
        <EuiButton disabled={busy||!confirm} onClick={()=>void mutate(true)}>Promote to incident</EuiButton>
      </>}
      {row.state==='promoted'&&row.incident_id&&<EuiButtonEmpty disabled={busy} onClick={()=>openRelated(row.incident_id!)}>Open linked incident</EuiButtonEmpty>}
    </EuiPanel>}
  </>;
}
