import React, { useState } from 'react';
import { EuiButton, EuiButtonEmpty, EuiCallOut, EuiFormRow, EuiSpacer, EuiText, EuiTextArea, EuiTitle } from '@elastic/eui';
import { evaluateReplay } from '../../../../common/incidents/tuning-evaluation';
const pct = (value: number | null) => value === null ? 'Not available' : (value * 100).toFixed(1) + '%';
export function IncidentTuningPanel({ back }: { back: () => void }) {
  const [input, setInput] = useState('');
  const [error, setError] = useState('');
  const [result, setResult] = useState<ReturnType<typeof evaluateReplay>>();
  function run() {
    setError(''); setResult(undefined);
    try {
      if (input.length > 1500000) throw new Error('Fixture exceeds size limit');
      setResult(evaluateReplay(JSON.parse(input)));
    } catch (e) { setError(e instanceof Error ? e.message : 'Invalid replay fixture'); }
  }
  return <>
    <EuiButtonEmpty onClick={back}>Back to incidents</EuiButtonEmpty>
    <EuiTitle size='l'><h1>Detection tuning evaluation</h1></EuiTitle>
    <EuiSpacer size='s' />
    <EuiCallOut title='Evaluate externally executed paired replay results'>This offline evaluator does not execute rules, collect labels, prove holdout independence, or change detections. Supply independently labelled benign and malicious samples and the observed baseline/candidate detection outcomes for each identical sample. Use opaque fixture IDs, not raw logs. No data is sent to a model or server.</EuiCallOut>
    <EuiSpacer size='m' />
    <EuiText size='s'><p>JSON format: baseline_version, candidate_version, split ("holdout"), rows (1–5,000 objects with id, label ("malicious", "benign" or "unknown"), baseline (boolean), candidate (boolean)). Use at least ten labelled samples of each class; this minimum is a review floor, not statistical certification.</p></EuiText>
    <EuiFormRow label='Paired replay fixture JSON' fullWidth><EuiTextArea fullWidth rows={12} value={input}
      onChange={event => { setInput(event.target.value); setResult(undefined); setError(''); }} maxLength={1500000} /></EuiFormRow>
    <EuiButton onClick={run} disabled={!input.trim()}>Evaluate tuning candidate</EuiButton>
    {error && <EuiCallOut color='danger' title={error} />}
    {result && <>
      <EuiSpacer size='l' />
      <EuiTitle size='s'><h2>{result.gate === 'blocked' ? 'Review gate blocked' : 'Eligible for human review only'}</h2></EuiTitle>
      <EuiText size='s'>
        <p>{result.baseline_version} → {result.candidate_version}. {result.total} paired samples: {result.malicious} malicious, {result.benign} benign, {result.unknown} unknown.</p>
        <table><thead><tr><th>Metric</th><th>Baseline</th><th>Candidate</th></tr></thead><tbody>
          {(['tp', 'fp', 'tn', 'fn'] as const).map(key => <tr key={key}><td>{key.toUpperCase()}</td><td>{result.baseline[key]}</td><td>{result.candidate[key]}</td></tr>)}
          <tr><td>Recall</td><td>{pct(result.baselineRecall)}</td><td>{pct(result.candidateRecall)}</td></tr>
          <tr><td>False-positive rate</td><td>{pct(result.baselineFalsePositiveRate)}</td><td>{pct(result.candidateFalsePositiveRate)}</td></tr>
        </tbody></table>
        <p>Benign alert reduction: {pct(result.benignAlertReduction)}. Lost malicious detections: {result.lostMalicious}; gained: {result.gainedMalicious}. Removed benign alerts: {result.removedBenign}; new: {result.addedBenign}. Changed unknown outcomes: {result.unknownChanged}.</p>
        {result.reasons.length > 0 && <ul>{result.reasons.map(reason => <li key={reason}>{reason.replace(/_/g, ' ')}</li>)}</ul>}
        <p>These are fixture-specific results, not a production detection performance estimate or approval to deploy. Validate labels, rule/version provenance, representativeness and coverage independently.</p>
      </EuiText>
    </>}
  </>;
}
