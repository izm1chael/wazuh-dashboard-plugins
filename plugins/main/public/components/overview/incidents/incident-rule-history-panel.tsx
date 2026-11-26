import React, { useEffect, useRef, useState } from 'react';
import { EuiButton, EuiCallOut, EuiFormRow, EuiSelect, EuiSpacer, EuiText, EuiTitle } from '@elastic/eui';
import { getHttp } from '../../../kibana-services';
import type { IncidentSummary } from '../../../../common/incidents/contracts';
import { inspectPage, RULE_UUID, RuleHistory, CLASSIFICATIONS } from '../../../../common/incidents/rule-history';
import type { IncidentApi } from './incident-api';

export function IncidentRuleHistoryPanel({ incident, api, disabled }: { incident: IncidentSummary; api: IncidentApi; disabled: boolean }) {
  const [rules, setRules] = useState<string[]>();
  const [rule, setRule] = useState('');
  const [report, setReport] = useState<RuleHistory>();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(false);
  const mounted = useRef(true), running = useRef(false);
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; }; }, []);
  async function work(load: boolean) {
    if (disabled || running.current) return;
    running.current = true; setBusy(true); setError(false); setReport(undefined);
    try {
      if (load) {
        const page = await api.findings(incident.id, 0, incident.revision);
        const ids = [...new Set(inspectPage(incident, page, 25).rules)].sort();
        if (mounted.current) { setRules(ids); setRule(ids[0] ?? ''); }
      } else {
        const data = await getHttp().get<RuleHistory>('/indexer/incidents/' + encodeURIComponent(incident.id) + '/rule-history',
          { query: { expected_revision: incident.revision, rule_uuid: rule } });
        if (data.scope !== 'recently_updated_currently_closed_sample' || data.rule_uuid !== rule ||
            data.observed_revision !== incident.revision || data.scanned_incidents !== data.matched_incidents + data.complete_nonmatches + data.uncertain_nonmatches ||
            data.matched_incidents !== CLASSIFICATIONS.reduce((sum, key) => sum + data.classifications[key], 0) + data.unknown_classification) {
          throw new Error('Invalid history report');
        }
        if (mounted.current) setReport(data);
      }
    } catch (_) { if (mounted.current) setError(true); }
    finally { running.current = false; if (mounted.current) setBusy(false); }
  }
  return <>
    <EuiTitle size='s'><h2>Detection history</h2></EuiTitle>
    <EuiText size='s'><p>Compare a visible exact Wazuh rule UUID with up to ten other currently closed incidents, ordered by latest update. At most five linked finding positions per incident. This is a bounded live sample, not a detection false-positive rate or complete historical cohort.</p></EuiText>
    <EuiButton disabled={disabled || busy} onClick={() => void work(true)}>Load visible rule identities</EuiButton>
    {rules && (rules.length ? <>
      <EuiFormRow label='Observed Wazuh rule UUID'><EuiSelect value={rule} disabled={busy || disabled}
        options={rules.map(value => ({ value, text: value }))} onChange={event => { setRule(event.target.value); setReport(undefined); }} /></EuiFormRow>
      <EuiButton disabled={disabled || busy || !RULE_UUID.test(rule)} onClick={() => void work(false)}>Compare recent closed incidents</EuiButton>
    </> : <EuiText size='s'>No unambiguous Wazuh rule UUID visible in the first 25 linked positions.</EuiText>)}
    {busy && <EuiText size='s'>Reading bounded caller-visible evidence…</EuiText>}
    {error && <EuiCallOut color='warning' title='Detection history unavailable or incident changed'>Reload before retrying. No incomplete search is presented as a complete cohort.</EuiCallOut>}
    {report && <>
      <EuiSpacer size='s' />
      <EuiText size='s'><p>Matched {report.matched_incidents} of {report.scanned_incidents} scanned incidents; {report.complete_nonmatches} fully inspected nonmatches, {report.uncertain_nonmatches} uncertain nonmatches. {report.more_closed_incidents ? 'Additional closed incidents were not scanned.' : 'No further closed incidents in this queue response.'}</p>
        <ul>{CLASSIFICATIONS.map(key => <li key={key}>{key.replace(/_/g, ' ')}: {report.classifications[key]}</li>)}<li>Unknown classification: {report.unknown_classification}</li></ul>
        <p>Matched incidents with partial coverage: {report.matched_with_partial_coverage}. Visible findings: {report.visible_findings}; unavailable: {report.unavailable_findings}; uninspected: {report.uninspected_links}; visible without exact rule UUID: {report.missing_rule_identity}.</p>
        <p>Incident closure classifications do not label individual findings; multiple rules may be involved. Rule UUID is not rule-version provenance. Current visibility, retention and concurrent changes limit this sample.</p>
      </EuiText>
    </>}
  </>;
}
