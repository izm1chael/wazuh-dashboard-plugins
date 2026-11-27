import React, { useEffect, useRef, useState } from 'react';
import { EuiBasicTable, EuiBasicTableColumn, EuiButton, EuiButtonEmpty, EuiCallOut, EuiFieldText, EuiFormRow, EuiPanel, EuiSelect, EuiSpacer, EuiText, EuiTextArea, EuiTitle } from '@elastic/eui';
import { DetectionRelease, ReleaseDay, ReleaseReviewInput, releaseHash, validateRelease, validateReleaseDay, validateReleasePage, validateReviewInput } from '../../../../common/incidents/detection-release-contract';
import { parseCampaignPack } from '../../../../common/incidents/native-campaign-contract';
import { getHttp } from '../../../kibana-services';

const ROOT='/indexer/detection-releases';
const stateLabel=(r:DetectionRelease)=>r.state==='approved'&&r.review?.expires&&Date.parse(r.review.expires)<=Date.now()?'Approved — expired':
  r.state==='reserved'?'Reserved — outcome unresolved':r.state==='native_reported'?'Native response recorded':r.state;
export function DetectionReleasePanel({back,backtesting}:{back:()=>void;backtesting:()=>void}){
  const [day,setDay]=useState(()=>new Date().toISOString().slice(0,10)),[page,setPage]=useState<ReleaseDay>();
  const [id,setId]=useState(''),[row,setRow]=useState<DetectionRelease>(),[raw,setRaw]=useState('');
  const [decision,setDecision]=useState<'approved'|'rejected'>('approved'),[reason,setReason]=useState('');
  const [deployer,setDeployer]=useState(''),[expiry,setExpiry]=useState('');
  const [confirmed,setConfirmed]=useState(false),[busy,setBusy]=useState(false),[error,setError]=useState('');
  const active=useRef(false),generation=useRef(0);
  useEffect(()=>()=>{generation.current++;},[]);
  let pack:ReturnType<typeof parseCampaignPack>|undefined;
  try{pack=parseCampaignPack(raw);}catch(_){/* incomplete input */}
  const eligible=pack?.status==='ready_for_independent_release_review';
  const canRead=()=>{try{releaseHash(id);return true;}catch(_){return false;}};
  const canLoad=()=>{try{validateReleaseDay(day+'T00:00:00Z');return true;}catch(_){return false;}};
  const resetConfirm=()=>setConfirmed(false);
  const select=(value:string)=>{setId(value);setRow(undefined);setConfirmed(false);setReason('');setDeployer('');setExpiry('');};
  async function run(work:()=>Promise<DetectionRelease|ReleaseDay>,kind:'day'|'row'){
    if(active.current)return;
    const seq=++generation.current;active.current=true;setBusy(true);setConfirmed(false);setError('');
    try{
      const result=await work();
      if(seq!==generation.current)return;
      if(kind==='day')setPage(result as ReleaseDay);
      else{
        const next=result as DetectionRelease;setRow(next);setId(next.id);setPage(undefined);setReason('');setDeployer('');setExpiry('');
      }
    }catch(_){
      if(seq===generation.current){
        setRow(undefined);setPage(undefined);
        setError('Operation or refresh unavailable. Read the exact release again before retrying. A previous write may have committed; do not assume a failed response means no change.');
      }
    }finally{active.current=false;if(seq===generation.current)setBusy(false);}
  }
  const read=()=>run(async()=>{
    const requested=releaseHash(id),result=validateRelease(await getHttp().post<DetectionRelease>(ROOT+'/read',{body:JSON.stringify({id:requested})}));
    if(result.id!==requested)throw Error('Release changed');return result;
  },'row');
  const loadDay=()=>run(async()=>{
    const requested=validateReleaseDay(day+'T00:00:00Z');
    return validateReleasePage(await getHttp().post<ReleaseDay>(ROOT+'/day',{body:JSON.stringify({day:requested})}),requested);
  },'day');
  const submit=()=>run(async()=>{
    if(!pack||!eligible||!confirmed)throw Error('No confirmed eligible pack');
    const result=validateRelease(await getHttp().post<DetectionRelease>(ROOT+'/submit',{body:JSON.stringify({pack_json:raw})}));
    if(result.id!==pack.review_plan_sha256||result.state!=='submitted')throw Error('Unexpected release');return result;
  },'row');
  let reviewInput:ReleaseReviewInput|undefined;
  try{
    if(row?.state==='submitted'&&eligible&&pack?.review_plan_sha256===row.id){
      reviewInput=validateReviewInput({id:row.id,pack_json:raw,decision,reason,
        deployer:decision==='approved'?deployer:null,expires:decision==='approved'?expiry:null});
    }
  }catch(_){/* invalid review */}
  const review=()=>run(async()=>{
    if(!reviewInput||!confirmed)throw Error('No confirmed review');
    const result=validateRelease(await getHttp().post<DetectionRelease>(ROOT+'/review',{body:JSON.stringify(reviewInput)}));
    if(result.id!==reviewInput.id||result.state!==reviewInput.decision)throw Error('Unexpected review');return result;
  },'row');
  const columns:Array<EuiBasicTableColumn<DetectionRelease>>=[
    {field:'submitted_at',name:'Submitted (UTC)'},{field:'author',name:'Submitter'},
    {name:'Rules',render:r=>r.evidence.changed_rules.length},{name:'State',render:r=>stateLabel(r)},
    {name:'Plan',render:r=><EuiButtonEmpty disabled={busy} onClick={()=>select(r.id)}>{r.id.slice(0,16)}… inspect</EuiButtonEmpty>}
  ];
  return <>
    <EuiButtonEmpty onClick={back}>Back to incidents</EuiButtonEmpty>
    <EuiButtonEmpty onClick={backtesting}>Historical and shadow backtesting</EuiButtonEmpty>
    <EuiTitle size='l'><h1>Detection release management</h1></EuiTitle>
    <EuiCallOut title='Authenticated review, controlled native deployment'>
      Release metadata is shared with authorized release readers. Submit an eligible rule-only campaign pack, then independently review the identical text.
      The server verifies aggregate consistency and records authenticated actors; it cannot establish label truth or replay provenance.
      Native promotion remains separate, requiring a distinct deployer, exact plan, matching configured expiry and a one-use reservation. No deployment control here.
    </EuiCallOut>
    <EuiSpacer size='m'/>
    <EuiFormRow label='Submission day (UTC YYYY-MM-DD)'><EuiFieldText value={day} maxLength={10} disabled={busy} onChange={e=>{setDay(e.target.value);setPage(undefined);}}/></EuiFormRow>
    <EuiButton disabled={!canLoad()||busy} isLoading={busy} onClick={()=>void loadDay()}>Load release queue</EuiButton>
    {page&&<EuiBasicTable<DetectionRelease> items={page.rows} columns={columns} itemId='id' noItemsMessage='No releases submitted this day'/>}
    <EuiFormRow label='Exact native plan SHA-256'><EuiFieldText value={id} maxLength={64} disabled={busy} onChange={e=>select(e.target.value)}/></EuiFormRow>
    <EuiButton disabled={!canRead()||busy} onClick={()=>void read()}>Read exact release</EuiButton>
    {error&&<EuiCallOut color='warning' title='Release action unavailable'>{error}</EuiCallOut>}
    <EuiSpacer size='m'/>
    <EuiFormRow label='Original campaign pack JSON (identical text for submit and review)'>
      <EuiTextArea value={raw} maxLength={500000} disabled={busy} onChange={e=>{setRaw(e.target.value);resetConfirm();}}/>
    </EuiFormRow>
    {pack&&<EuiText size='s'><p>Plan {pack.review_plan_sha256}; {pack.changed_rules.length} changed rules. {eligible?'Eligible for independent review.':'Blocked; cannot submit.'}</p></EuiText>}
    {(!row||row.id!==pack?.review_plan_sha256)&&<><label><input type='checkbox' checked={confirmed} disabled={busy} onChange={e=>setConfirmed(e.target.checked)}/> Confirm submission of reviewed campaign metadata; original receipts and labels retained securely outside this ledger.</label>
      <EuiButton disabled={!eligible||!confirmed||busy} onClick={()=>void submit()}>Submit release</EuiButton></>}
    {row&&<EuiPanel hasBorder hasShadow={false}>
      <EuiTitle size='s'><h2>{stateLabel(row)}</h2></EuiTitle>
      <EuiText size='s'><p>Plan {row.id}; revision {row.revision}; submitted by {row.author} at {row.submitted_at}.</p>
        <p>Pack text digest {row.evidence.pack_sha256}.</p>
        <p>Integration {row.evidence.integration}; scope {row.evidence.cluster} / {row.evidence.space} / {row.evidence.dataset}.</p>
        <p>Historical events {row.evidence.historical_events}; prospective events {row.evidence.prospective_events}; elapsed hours {row.evidence.prospective_seconds/3600}.</p>
        {row.evidence.changed_rules.map(rule=><details key={rule}><summary>Rule {rule}</summary>
          <p>Historical: removed false positives {row.evidence.historical_metrics[rule].removed_false_positive}; gained positives {row.evidence.historical_metrics[rule].gained_positive}.</p>
          <p>Prospective: removed false positives {row.evidence.prospective_metrics[rule].removed_false_positive}; gained positives {row.evidence.prospective_metrics[rule].gained_positive}. No lost positives or new false positives in submitted aggregates.</p>
        </details>)}
        {row.review&&<p>Reviewed by {row.review.actor} at {row.review.at}: {row.review.decision} — {row.review.reason}.</p>}
        {row.review?.expires&&<p>Intended deployer {row.review.deployer}; expiry {row.review.expires}. Operator must configure this exact plan and expiry consistently on all nodes with the native freeze enabled.</p>}
        {row.reservation&&<p>One-use reservation by {row.reservation.actor} at {row.reservation.at}; never retry this plan blindly.</p>}
        {row.outcome&&<p>Native status {row.outcome.native_status}, recorded {row.outcome.at}. Native acceptance does not verify deployed detection behaviour or detector synchronisation.</p>}
      </EuiText>
      {row.state==='submitted'&&<>
        <EuiFormRow label='Independent review decision'><EuiSelect value={decision} disabled={busy} options={[{value:'approved',text:'Approve exact release'},{value:'rejected',text:'Reject permanently'}]}
          onChange={e=>{setDecision(e.target.value as 'approved'|'rejected');resetConfirm();}}/></EuiFormRow>
        <EuiFormRow label='Review reason'><EuiTextArea value={reason} maxLength={1024} disabled={busy} onChange={e=>{setReason(e.target.value);resetConfirm();}}/></EuiFormRow>
        {decision==='approved'&&<>
          <EuiFormRow label='Distinct authenticated deployer username'><EuiFieldText value={deployer} maxLength={1024} disabled={busy} onChange={e=>{setDeployer(e.target.value);resetConfirm();}}/></EuiFormRow>
          <EuiFormRow label='Expiry (UTC YYYY-MM-DDTHH:MM:SSZ, within one hour)'><EuiFieldText value={expiry} maxLength={20} disabled={busy} onChange={e=>{setExpiry(e.target.value);resetConfirm();}}/></EuiFormRow>
        </>}
        <label><input type='checkbox' checked={confirmed} disabled={busy} onChange={e=>setConfirmed(e.target.checked)}/> Confirm independent inspection of original labelled evidence, exact native preview and plan. This decision is permanent; no approval reuse.</label>
        <EuiButton disabled={!reviewInput||!confirmed||busy} onClick={()=>void review()}>Record independent decision</EuiButton>
      </>}
    </EuiPanel>}
  </>;
}
