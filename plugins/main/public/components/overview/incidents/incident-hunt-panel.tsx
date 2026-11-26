import React, { useEffect, useRef, useState } from 'react';
import { EuiBasicTable, EuiBasicTableColumn, EuiButton, EuiButtonEmpty, EuiCallOut, EuiFieldText, EuiFormRow, EuiSelect, EuiSpacer, EuiText, EuiTextArea, EuiTitle } from '@elastic/eui';
import { HUNT_FIELDS, HuntField, HuntInput, HuntReport, HuntRow, validateHunt, validateHuntReport } from '../../../../common/incidents/hunt-contract';
import { EntityInvestigation, validateEntityInvestigation, exportHuntDefinition, importHuntDefinition } from '../../../../common/incidents/entity-investigation';
import { EntityInvestigationResults } from './entity-investigation-results';
import { getHttp } from '../../../kibana-services';
import type { IndexerIncidentCommand } from '../../../../common/incidents/contracts';

type Props = {
  initial?: { field: HuntField; value?: string; values?: string[]; from?: string; until?: string };
  disabled?: boolean;
  attach?: (command: IndexerIncidentCommand) => Promise<void>;
  back?: () => void;
  openRelated?: (id: string) => void;
  saveBookmark?: (command: IndexerIncidentCommand) => Promise<void>;
};
type Run = { input: HuntInput; report: HuntReport; investigation?: EntityInvestigation };

export function IncidentHuntPanel({ initial, disabled = false, attach, back, openRelated, saveBookmark }: Props) {
  const [field, setField] = useState<HuntField>(initial?.field ?? 'source.ip');
  const [values, setValues] = useState(initial?.values?.join('\n') ?? initial?.value ?? '');
  const [until, setUntil] = useState(() => initial?.until ?? new Date().toISOString());
  const [from, setFrom] = useState(() => initial?.from ?? new Date(Date.parse(until) - 86400000).toISOString());
  const [bookmarkLabel, setBookmarkLabel] = useState('');
  const [shareConfirmed, setShareConfirmed] = useState(false);
  const [definition, setDefinition] = useState('');
  const [definitionError, setDefinitionError] = useState(false);
  const [run, setRun] = useState<Run>();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const generation = useRef(0);
  const active = useRef(false);
  useEffect(() => () => { generation.current++; }, []);
  let input: HuntInput | undefined;
  try {
    input = validateHunt({ field, values: values.split(/\r?\n/).filter(v => v.length > 0), from, until });
  } catch (_) { /* invalid form */ }
  const reset = () => { setRun(undefined); setError(''); setShareConfirmed(false); };
  async function search(investigate = false) {
    if (!input || disabled || active.current) return;
    const request = input;
    const current = ++generation.current;
    active.current = true; setLoading(true); reset();
    try {
      if (investigate) {
        const report = validateEntityInvestigation(await getHttp().post<EntityInvestigation>('/indexer/incident-entity/investigate', { body: JSON.stringify(request) }),request);
        if (generation.current === current) setRun({ input:request, report:report.hunt, investigation:report });
        return;
      }
      const report = await getHttp().post<HuntReport>('/indexer/incident-hunt/search', { body: JSON.stringify(request) });
      if (generation.current === current) setRun({ input: request, report: validateHuntReport(report, request) });
    } catch (_) {
      if (generation.current === current) setError('Hunt unavailable or incomplete. Check access, field mapping, or narrow the time range. No partial results are displayed.');
    } finally {
      active.current = false;
      if (generation.current === current) setLoading(false);
    }
  }
  const locked = disabled || loading;
  const columns: Array<EuiBasicTableColumn<HuntRow>> = [
    { field: 'timestamp', name: 'Observed (UTC)' },
    { field: 'index', name: 'Finding index' },
    { field: 'document_id', name: 'Finding ID' },
    { name: 'Exact matched values', render: (row: HuntRow) => row.matched_values.join(', ') },
  ];
  if (attach) columns.push({ name: 'Action', render: (row: HuntRow) => <EuiButtonEmpty disabled={locked}
    onClick={() => void attach({ kind: 'attach-finding', index: row.index, document_id: row.document_id })}>Attach finding</EuiButtonEmpty> });
  return <>
    {back && <EuiButtonEmpty onClick={back}>Back to incidents</EuiButtonEmpty>}
    <EuiTitle size={back ? 'l' : 's'}><h2>Historical entity / IOC hunt</h2></EuiTitle>
    <EuiText size='s'>Search currently accessible Wazuh findings only. Choose an exact source field and up to 20 literal values, one per line (OR). Maximum seven days and 100 findings. IP searches currently accept IPv4 only. Case and spelling must match source values; no wildcard, CIDR, external intelligence or unrestricted query syntax.</EuiText>
    <EuiSpacer size='s' />
    <EuiFormRow label='Exact finding field'><EuiSelect value={field} disabled={locked}
      options={HUNT_FIELDS.map(value => ({ value, text: value }))} onChange={e => { reset(); setField(e.target.value as HuntField); }} /></EuiFormRow>
    <EuiFormRow label='Entity or IOC values' helpText='One exact value per line. Do not enter secrets.'>
      <EuiTextArea value={values} disabled={locked} maxLength={5140} onChange={e => { reset(); setValues(e.target.value); }} />
    </EuiFormRow>
    <EuiFormRow label='From (UTC, inclusive)'><EuiFieldText value={from} disabled={locked} maxLength={30} onChange={e => { reset(); setFrom(e.target.value); }} /></EuiFormRow>
    <EuiFormRow label='Until (UTC, exclusive)'><EuiFieldText value={until} disabled={locked} maxLength={30} onChange={e => { reset(); setUntil(e.target.value); }} /></EuiFormRow>
    <EuiButton disabled={locked || !input} onClick={() => void search()}>{loading ? 'Searching…' : 'Run exact hunt'}</EuiButton>
    <EuiButton disabled={locked || !input} onClick={() => void search(true)}>Investigate entity and related cases</EuiButton>
    <EuiButtonEmpty disabled={loading || (!run && !error)} onClick={reset}>Clear results</EuiButtonEmpty>
    <EuiSpacer size='s' />
    <details><summary>Portable saved hunt definition</summary>
      <EuiText size='s'>Copy the exact query definition to approved storage if permitted. It contains entity values and timestamps, not results or credentials. Do not save sensitive queries in shared or untrusted locations. Nothing is automatically persisted in the browser.</EuiText>
      <EuiButtonEmpty disabled={locked || !input} onClick={()=>{if(input){setDefinition(exportHuntDefinition(input));setDefinitionError(false);}}}>Generate definition</EuiButtonEmpty>
      <EuiFormRow label='Hunt definition JSON'><EuiTextArea value={definition} maxLength={16384} disabled={locked}
        onChange={e=>{setDefinition(e.target.value);setDefinitionError(false);}} /></EuiFormRow>
      <EuiButtonEmpty disabled={locked || !definition} onClick={()=>{
        try { const query=importHuntDefinition(definition);reset();setField(query.field);setValues(query.values.join('\n'));setFrom(query.from);setUntil(query.until);setDefinitionError(false); }
        catch (_) { setDefinitionError(true); }
      }}>Load definition without executing</EuiButtonEmpty>
      <EuiButtonEmpty disabled={locked || !definition} onClick={()=>{setDefinition('');setDefinitionError(false);}}>Clear definition</EuiButtonEmpty>
      {definitionError && <EuiCallOut color='warning' title='Invalid or unsupported hunt definition' />}
    </details>
    {saveBookmark && <details><summary>Save query to this incident</summary>
      <EuiText size='s'>The exact field, values and time range become shared incident metadata and remain in audit history after withdrawal. Only save non-restricted values. No query results are stored.</EuiText>
      <EuiFormRow label='Bookmark label'><EuiFieldText value={bookmarkLabel} maxLength={128} disabled={locked}
        onChange={e=>{setBookmarkLabel(e.target.value);setShareConfirmed(false);}} /></EuiFormRow>
      <label><input type='checkbox' checked={shareConfirmed} disabled={locked} onChange={e=>setShareConfirmed(e.target.checked)} /> I confirm these query values may be shared with case readers.</label>
      <EuiButtonEmpty disabled={locked || !input || !shareConfirmed || !bookmarkLabel.trim() || bookmarkLabel!==bookmarkLabel.trim() || /[\x00-\x1f\x7f-\x9f]/.test(bookmarkLabel)}
        onClick={()=>{if(input && shareConfirmed){setShareConfirmed(false);void saveBookmark({kind:'save-hunt-bookmark',label:bookmarkLabel,query:input});}}}>Save case bookmark</EuiButtonEmpty>
    </details>}
    {!input && <EuiText size='s'>Enter valid unique literal values and a UTC range of no more than seven days.</EuiText>}
    {error && <EuiCallOut color='warning' title='Hunt not completed'>{error}</EuiCallOut>}
    {run && <>
      <EuiSpacer size='m' />
      <EuiText size='s'>{run.report.match_count} distinct matched findings for {run.input.field} between {run.input.from} and {run.input.until}.</EuiText>
      <EuiText size='s'>Counts are within this caller-visible, exact-field, retained-findings query only. A zero result is not evidence of absence or benignity; a match is not a confirmed malicious event.</EuiText>
      {run.input.values.map(value => <EuiText key={value} size='s'>{value}: {run.report.rows.filter(row => row.matched_values.includes(value)).length} matching finding(s)</EuiText>)}
      {run.investigation && <EntityInvestigationResults report={run.investigation} disabled={locked} openRelated={openRelated} />}
      <EuiBasicTable<HuntRow> items={run.report.rows} columns={columns} noItemsMessage='No exact matches in this search scope' />
      {attach && <EuiText size='s'>Attachment is a separate explicit action. The indexer rechecks source visibility, ownership and incident revision.</EuiText>}
    </>}
    <EuiSpacer size='m' />
  </>;
}
