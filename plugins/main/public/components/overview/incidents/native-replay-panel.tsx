import React, { useState } from 'react';
import { EuiButton, EuiButtonEmpty, EuiCallOut, EuiFieldText, EuiFormRow, EuiPanel, EuiSelect, EuiSpacer, EuiText, EuiTextArea, EuiTitle } from '@elastic/eui';
import { NativeReplayReceipt, ReplayLabels, ReplayLabel, parseNativeReplay, validateReplayLabels, pairedReview } from '../../../../common/incidents/native-replay-contract';

export function NativeReplayPanel({back}:{back:()=>void}){
  const [raw,setRaw]=useState(''),[labelRaw,setLabelRaw]=useState('');
  const [receipt,setReceipt]=useState<NativeReplayReceipt>(),[labels,setLabels]=useState<ReplayLabels>();
  const [rule,setRule]=useState(''),[error,setError]=useState('');
  const [partition,setPartition]=useState<'tuning'|'holdout'>('holdout');
  const [selected,setSelected]=useState('');
  const selectedRow=receipt?.rows.find(row=>JSON.stringify([row.index,row.id])===selected);
  const review=receipt&&labels?pairedReview(receipt,labels,partition):undefined;
  function load(){
    try{setReceipt(parseNativeReplay(raw));setLabels(undefined);setLabelRaw('');setSelected('');setError('');}
    catch(_){setReceipt(undefined);setLabels(undefined);setError('Invalid or inconsistent native replay receipt.');}
  }
  function template(){
    if(!receipt)return;
    const result:ReplayLabels={format:'wazuh-native-replay-labels-v1',rule_uuid:rule,labels:receipt.rows.map(row=>({
      index:row.index,id:row.id,source_sha256:row.source_sha256,truth:'unknown',partition:'tuning'}))};
    try{validateReplayLabels(result,receipt);setLabelRaw(JSON.stringify(result,null,2));setLabels(undefined);setError('');}
    catch(_){setError('Enter an exact rule UUID before creating a label template.');}
  }
  function loadLabels(){
    try{
      if(!receipt||labelRaw.length>1000000)throw Error('Invalid labels');
      setLabels(validateReplayLabels(JSON.parse(labelRaw),receipt));setError('');
    }catch(_){setLabels(undefined);setError('Invalid labels or event identity/source hash mismatch.');}
  }
  const edit=(truth:ReplayLabel['truth'])=>{
    if(!labels||!selectedRow||!receipt)return;
    const next:ReplayLabels={...labels,labels:labels.labels.map(row=>row.index===selectedRow.index&&row.id===selectedRow.id?
      {...row,truth,partition}:row)};
    setLabels(validateReplayLabels(next,receipt));setLabelRaw(JSON.stringify(next,null,2));
  };
  return <>
    <EuiButtonEmpty onClick={back}>Back to incidents</EuiButtonEmpty>
    <EuiTitle size='l'><h1>Native rule backtesting and tuning review</h1></EuiTitle>
    <EuiCallOut title='Test versus Custom — no automatic promotion'>
      Replay the same retained normalized events through native Content Manager detection logtest. Import the runner receipt here to compare gained and lost rule matches.
      Receipts and labels are local operator assertions, not signatures or promotion authorization. Rule-content fingerprints do not establish decoder or mapping parity.
      Keep Test → Custom frozen during testing; use the native workflow after independent review.
    </EuiCallOut>
    <EuiSpacer size='m'/>
    <EuiFormRow label='Native replay receipt JSON'><EuiTextArea value={raw} maxLength={8000000} onChange={e=>{setRaw(e.target.value);setReceipt(undefined);setLabels(undefined);setError('');}} /></EuiFormRow>
    <EuiButton disabled={!raw} onClick={load}>Inspect receipt</EuiButton>
    {error&&<EuiCallOut color='warning' title={error}/>}
    {receipt&&<>
      <EuiSpacer size='m'/>
      <EuiPanel hasBorder hasShadow={false}>
        <EuiText size='s'><p>Integration: {receipt.scope.integration}; dataset {receipt.scope.dataset}; cluster {receipt.scope.cluster}; source space {receipt.scope.space}.</p>
          <p>Historical comparison: {receipt.scope.from} — {receipt.scope.until}. Observed {receipt.observed_at}.</p>
          <p>{receipt.event_count} exact retained events; Custom {receipt.baseline_matches} matches; Test {receipt.candidate_matches} matches; gained {receipt.gained_matches}; lost {receipt.lost_matches}.</p>
          <p>Test fingerprint: {receipt.test_sha256}. Custom fingerprint: {receipt.custom_sha256}. Promotion preview digest: {receipt.preview_sha256}.</p>
          <p>Matches are event/rule pairs, not incident counts. Unlabelled reductions are not false-positive reductions.</p>
        </EuiText>
        <EuiFormRow label='Exact selected rule UUID'><EuiFieldText value={rule} maxLength={36} onChange={e=>{setRule(e.target.value);setLabels(undefined);}} /></EuiFormRow>
        <EuiButtonEmpty onClick={template}>Generate unknown-label template</EuiButtonEmpty>
        <EuiFormRow label='Independent labels JSON'><EuiTextArea value={labelRaw} maxLength={1000000} onChange={e=>{setLabelRaw(e.target.value);setLabels(undefined);}}/></EuiFormRow>
        <EuiButtonEmpty disabled={!labelRaw} onClick={loadLabels}>Validate labels</EuiButtonEmpty>
        <EuiText size='s'>Assign truth independently of the rule result, and holdout membership before tuning. Unknowns are not treated as negatives. This local editor cannot verify label provenance or that a holdout was unseen.</EuiText>
        <EuiFormRow label='Partition'><EuiSelect value={partition} options={[{value:'tuning',text:'Tuning'},{value:'holdout',text:'Holdout'}]} onChange={e=>setPartition(e.target.value as 'tuning'|'holdout')}/></EuiFormRow>
        {review&&<EuiText size='s'>
          <h3>Selected rule {labels?.rule_uuid} — {review.status.replace(/_/g,' ')}</h3>
          <p>Positive {review.positives}; negative {review.negatives}; unknown {review.unknown}.</p>
          <table><thead><tr><th>Space</th><th>TP</th><th>FP</th><th>TN</th><th>FN</th></tr></thead><tbody>
          <tr><td>Custom</td><td>{review.baseline.tp}</td><td>{review.baseline.fp}</td><td>{review.baseline.tn}</td><td>{review.baseline.fn}</td></tr>
          <tr><td>Test</td><td>{review.candidate.tp}</td><td>{review.candidate.fp}</td><td>{review.candidate.tn}</td><td>{review.candidate.fn}</td></tr></tbody></table>
          <p>Lost true positives {review.lost_positives}; gained true positives {review.gained_positives}; new false positives {review.new_false_positives}; removed false positives {review.removed_false_positives}.</p>
          <p>Review candidate requires at least ten known positives and ten known negatives, no unknown labels in the partition, no lost positive or new false positive, and at least one improvement. This conservative heuristic is not a statistical qualification or a promotion gate.</p>
        </EuiText>}
        <EuiFormRow label='Inspect paired event result'><EuiSelect value={selected} options={[{value:'',text:'Choose a reference'},...receipt.rows.map(row=>({value:JSON.stringify([row.index,row.id]),text:row.index+' / '+row.id}))]} onChange={e=>setSelected(e.target.value)}/></EuiFormRow>
        {selectedRow&&<EuiText size='s'><p>Source digest: {selectedRow.source_sha256}</p><p>Custom rules: {selectedRow.baseline.join(', ')||'None'}</p>
          <p>Test rules: {selectedRow.candidate.join(', ')||'None'}</p><p>Gained: {selectedRow.gained.join(', ')||'None'}; lost: {selectedRow.lost.join(', ')||'None'}</p></EuiText>}
        {selectedRow&&labels&&<><EuiButtonEmpty onClick={()=>edit('positive')}>Set expected positive</EuiButtonEmpty><EuiButtonEmpty onClick={()=>edit('negative')}>Set expected negative</EuiButtonEmpty><EuiButtonEmpty onClick={()=>edit('unknown')}>Set unknown</EuiButtonEmpty></>}
      </EuiPanel>
    </>}
  </>;
}
