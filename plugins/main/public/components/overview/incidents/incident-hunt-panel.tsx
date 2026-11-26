import React, { useEffect, useRef, useState } from 'react';
import { EuiBasicTable, EuiBasicTableColumn, EuiButton, EuiButtonEmpty, EuiCallOut, EuiFieldText, EuiFormRow, EuiSelect, EuiSpacer, EuiText, EuiTextArea, EuiTitle } from '@elastic/eui';
import { HUNT_FIELDS, HuntField, HuntInput, HuntReport, HuntRow, validateHunt, validateHuntReport } from '../../../../common/incidents/hunt-contract';
import { getHttp } from '../../../kibana-services';
import type { IndexerIncidentCommand } from '../../../../common/incidents/contracts';

type Props = {
  initial?: { field: HuntField; value: string };
  disabled?: boolean;
  attach?: (command: IndexerIncidentCommand) => Promise<void>;
  back?: () => void;
};
type Run = { input: HuntInput; report: HuntReport };

export function IncidentHuntPanel({ initial, disabled = false, attach, back }: Props) {
  const [field, setField] = useState<HuntField>(initial?.field ?? 'source.ip');
  const [values, setValues] = useState(initial?.value ?? '');
  const [until, setUntil] = useState(() => new Date().toISOString());
  const [from, setFrom] = useState(() => new Date(Date.parse(until) - 86400000).toISOString());
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
  const reset = () => { setRun(undefined); setError(''); };
  async function search() {
    if (!input || disabled || active.current) return;
    const request = input;
    const current = ++generation.current;
    active.current = true; setLoading(true); reset();
    try {
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
    <EuiButtonEmpty disabled={loading || (!run && !error)} onClick={reset}>Clear results</EuiButtonEmpty>
    {!input && <EuiText size='s'>Enter valid unique literal values and a UTC range of no more than seven days.</EuiText>}
    {error && <EuiCallOut color='warning' title='Hunt not completed'>{error}</EuiCallOut>}
    {run && <>
      <EuiSpacer size='m' />
      <EuiText size='s'>{run.report.match_count} distinct matched findings for {run.input.field} between {run.input.from} and {run.input.until}.</EuiText>
      <EuiText size='s'>Counts are within this caller-visible, exact-field, retained-findings query only. A zero result is not evidence of absence or benignity; a match is not a confirmed malicious event.</EuiText>
      {run.input.values.map(value => <EuiText key={value} size='s'>{value}: {run.report.rows.filter(row => row.matched_values.includes(value)).length} matching finding(s)</EuiText>)}
      <EuiBasicTable<HuntRow> items={run.report.rows} columns={columns} noItemsMessage='No exact matches in this search scope' />
      {attach && <EuiText size='s'>Attachment is a separate explicit action. The indexer rechecks source visibility, ownership and incident revision.</EuiText>}
    </>}
    <EuiSpacer size='m' />
  </>;
}
