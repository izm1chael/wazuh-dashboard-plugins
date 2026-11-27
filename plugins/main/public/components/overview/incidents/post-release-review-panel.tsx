import React, { useState } from 'react';
import { EuiButton, EuiCallOut, EuiFormRow, EuiSpacer, EuiText, EuiTextArea, EuiTitle } from '@elastic/eui';
import { DetectionRelease } from '../../../../common/incidents/detection-release-contract';
import { PostReleaseReview, parsePostReleaseReview } from '../../../../common/incidents/post-release-contract';

export function PostReleaseReviewPanel({release}:{release:DetectionRelease}){
  const [raw,setRaw]=useState(''),[report,setReport]=useState<PostReleaseReview>(),[error,setError]=useState(false);
  function load(){
    try{setReport(parsePostReleaseReview(raw,release));setError(false);}
    catch(_){setReport(undefined);setError(true);}
  }
  return <>
    <EuiSpacer size='m'/><EuiTitle size='s'><h2>Post-release verification evidence</h2></EuiTitle>
    <EuiText size='s'>Import a read-only native_release_monitor.py receipt. It compares reviewed Test rule documents with current Custom documents and equal before/after event and finding windows. No automatic rollback, no detection success or false-positive-rate claim. The local receipt is not signed.</EuiText>
    <EuiFormRow label='Post-release observation JSON'><EuiTextArea value={raw} maxLength={100000} onChange={e=>{setRaw(e.target.value);setReport(undefined);setError(false);}}/></EuiFormRow>
    <EuiButton disabled={!raw} onClick={load}>Inspect post-release evidence</EuiButton>
    {error&&<EuiCallOut color='warning' title='Receipt inconsistent with this release'/>}
    {report&&<>
      <EuiCallOut color={report.content.integration_document_equal&&report.content.all_integration_rule_documents_equal?'primary':'warning'}
        title={report.content.integration_document_equal&&report.content.all_integration_rule_documents_equal?'Observed integration and rule documents match':'Content mismatch — independent investigation required'}>
        No detector synchronisation or actual detection execution verified.
      </EuiCallOut>
      <EuiText size='s'><p>Observed {report.observed_at}; baseline {report.windows.baseline_from} — {report.windows.baseline_until}; post {report.windows.post_from} — {report.windows.post_until}.</p>
        <p>Visible event counts: {report.baseline.events.count} → {report.post.events.count}. Reviewed-rule findings: {report.baseline.findings.count} → {report.post.findings.count}. Searches are separate populations, not a one-to-one event-to-finding join; absence is not verified telemetry coverage.</p>
        <table><thead><tr><th>Rule</th><th>Content equal</th><th>Before</th><th>After</th><th>Delta</th></tr></thead>
          <tbody>{report.rules.map((r,i)=><tr key={r.rule_uuid}><td>{r.rule_uuid}</td><td>{report.content.reviewed_rules[i].equal?'Yes':'No'}</td><td>{r.baseline_findings}</td><td>{r.post_findings}</td><td>{r.delta}</td></tr>)}</tbody></table>
      </EuiText>
    </>}
  </>;
}
