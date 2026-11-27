import React, { useState } from 'react';
import { EuiButton, EuiCallOut, EuiFormRow, EuiPanel, EuiSpacer, EuiText, EuiTextArea, EuiTitle } from '@elastic/eui';
import { CampaignPack, parseCampaignPack } from '../../../../common/incidents/native-campaign-contract';

export function NativeCampaignReview(){
  const [raw,setRaw]=useState(''),[pack,setPack]=useState<CampaignPack>(),[error,setError]=useState(false);
  function load(){
    try{setPack(parseCampaignPack(raw));setError(false);}
    catch(_){setPack(undefined);setError(true);}
  }
  return <EuiPanel hasBorder hasShadow={false}>
    <EuiTitle size='s'><h2>Historical holdout and prospective campaign review</h2></EuiTitle>
    <EuiText size='s'><p>Import an evidence pack from native_rule_campaign_review.py. This is a local review, not authenticated approval.
      Only existing rule updates are supported. The imported statistics and blockers are checked for internal consistency;
      original events, reviewer identity, label provenance and native plan equivalence are not independently verified here.</p></EuiText>
    <EuiFormRow label='Campaign evidence pack JSON'><EuiTextArea value={raw} maxLength={500000} onChange={e=>{setRaw(e.target.value);setPack(undefined);setError(false);}} /></EuiFormRow>
    <EuiButton disabled={!raw} onClick={load}>Review complete campaign</EuiButton>
    {error&&<EuiCallOut color='warning' title='Invalid or inconsistent campaign evidence pack'/>}
    {pack&&<>
      <EuiSpacer size='m'/>
      <EuiCallOut color={pack.blockers.length?'warning':'primary'} title={pack.blockers.length?'Blocked — do not promote':'Ready for independent release review — not authorized'}>
        <EuiText size='s'><p>{pack.historical_events} historical holdout events; {pack.prospective_events} prospective events across {pack.prospective_windows} closed windows ({pack.prospective_seconds/3600} hours).</p>
          {pack.blockers.length>0&&<ul>{pack.blockers.map(item=><li key={item}>{item}</li>)}</ul>}
          <p>Telemetry coverage unverified. No promotion permission is granted by this pack.</p></EuiText>
      </EuiCallOut>
      <EuiText size='s'><p>Scope: {pack.scope.integration} · {pack.scope.cluster} · {pack.scope.space} · {pack.scope.dataset}</p>
        <p>Author (attested): {pack.review_attestation.author}; independent reviewer (attested): {pack.review_attestation.reviewer}.</p>
        <p>Review reason: {pack.review_attestation.reason}</p>
        <p>Native reviewed plan SHA-256: {pack.review_plan_sha256}</p>
        <details><summary>Evidence fingerprints</summary><p>Test: {pack.test_sha256}</p><p>Custom: {pack.custom_sha256}</p>
          <p>Preview: {pack.preview_sha256}</p><p>Labels: {pack.labels_sha256}</p>
          <p>Historical receipts: {pack.historical_receipt_sha256.length}; prospective receipts: {pack.prospective_receipt_sha256.length}.</p></details>
        <p>Verify the original receipts, independently labelled evidence and native read-only plan digest before any release. Keep the production freeze enabled and configure only the approved digest and short expiry via operator change control.</p>
        {pack.changed_rules.map(rule=><details key={rule}><summary>Rule {rule}</summary>
          <table><thead><tr><th>Partition</th><th>Space</th><th>TP</th><th>FP</th><th>TN</th><th>FN</th><th>Unknown</th></tr></thead>
            <tbody>{(['historical','prospective'] as const).map(name=>{
              const m=name==='historical'?pack.historical_metrics[rule]:pack.prospective_metrics[rule];
              return <React.Fragment key={name}><tr><td>{name}</td><td>Custom</td><td>{m.baseline_tp}</td><td>{m.baseline_fp}</td><td>{m.baseline_tn}</td><td>{m.baseline_fn}</td><td>{m.unknown}</td></tr>
                <tr><td>{name}</td><td>Test</td><td>{m.candidate_tp}</td><td>{m.candidate_fp}</td><td>{m.candidate_tn}</td><td>{m.candidate_fn}</td><td>{m.unknown}</td></tr></React.Fragment>;
            })}</tbody></table>
          {(['historical','prospective'] as const).map(name=>{const m=name==='historical'?pack.historical_metrics[rule]:pack.prospective_metrics[rule];
            return <p key={name}>{name}: lost positives {m.lost_positive}; gained positives {m.gained_positive}; new false positives {m.new_false_positive}; removed false positives {m.removed_false_positive}.</p>;
          })}
        </details>)}
      </EuiText>
    </>}
  </EuiPanel>;
}
