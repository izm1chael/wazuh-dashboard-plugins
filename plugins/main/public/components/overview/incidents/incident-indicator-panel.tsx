import React, { useEffect, useRef, useState } from 'react';
import { EuiBasicTable, EuiBasicTableColumn, EuiButton, EuiButtonEmpty, EuiCallOut, EuiFieldText, EuiFormRow, EuiSelect, EuiSpacer, EuiText, EuiTextArea, EuiTitle } from '@elastic/eui';
import { getHttp } from '../../../kibana-services';
import { Indicator, IndicatorCatalog, IndicatorInput, IndicatorType, INDICATOR_TYPES, INDICATOR_TLP, validateIndicator, validateCatalog, validateMutation, huntFields } from '../../../../common/incidents/indicator-contract';
import { exportStix, importStix } from '../../../../common/incidents/stix-indicator-exchange';
import type { Tlp } from '../../../../common/incidents/contracts';
import type { HuntField } from '../../../../common/incidents/hunt-contract';
import { IncidentHuntPanel } from './incident-hunt-panel';

const ROOT = '/indexer/incident-indicators/';
const DAY = 86400000;
const initialDates = () => { const now = Date.now(); return { valid_from: new Date(now).toISOString(), valid_until: new Date(now + 30 * DAY).toISOString() }; };
function bundleUuid(): string {
  const bytes = window.crypto.getRandomValues(new Uint8Array(16));
  bytes[6] = (bytes[6] & 15) | 64; bytes[8] = (bytes[8] & 63) | 128;
  const hex = Array.from(bytes, v => v.toString(16).padStart(2, '0')).join('');
  return [hex.slice(0, 8), hex.slice(8, 12), hex.slice(12, 16), hex.slice(16, 20), hex.slice(20)].join('-');
}

export function IncidentIndicatorPanel({ back }: { back: () => void }) {
  const [catalog, setCatalog] = useState<IndicatorCatalog>();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [filter, setFilter] = useState('all');
  const [search, setSearch] = useState('');
  const [type, setType] = useState<IndicatorType>('ipv4');
  const [value, setValue] = useState('');
  const [source, setSource] = useState('');
  const [confidence, setConfidence] = useState('');
  const [tlp, setTlp] = useState<Tlp>('TLP:AMBER');
  const [dates, setDates] = useState(initialDates);
  const [stix, setStix] = useState('');
  const [preview, setPreview] = useState<IndicatorInput[]>();
  const [exported, setExported] = useState('');
  const [selected, setSelected] = useState('');
  const [reason, setReason] = useState('');
  const [sightingAt, setSightingAt] = useState('');
  const [sightingSource, setSightingSource] = useState('');
  const [sightingCount, setSightingCount] = useState('');
  const [withdrawRevision, setWithdrawRevision] = useState<number>();
  const [withdrawReason, setWithdrawReason] = useState('');
  const [hunt, setHunt] = useState<{ id: string; field: HuntField; value?: string; values?: string[]; from: string; until: string }>();
  const [batchType, setBatchType] = useState<IndicatorType>('ipv4');
  const generation = useRef(0);
  const running = useRef(false);
  useEffect(() => {
    void reload();
    return () => { generation.current++; };
  }, []);
  async function fetchCatalog() {
    return validateCatalog(await getHttp().post<IndicatorCatalog>(ROOT + 'read', { body: '{}' }));
  }
  function clearDerived() {
    setPreview(undefined); setExported(''); setHunt(undefined); setSelected(''); setReason(''); setSightingAt(''); setSightingSource(''); setSightingCount(''); setWithdrawRevision(undefined); setWithdrawReason('');
  }
  async function reload() {
    if (running.current) return;
    running.current = true; const run = ++generation.current;
    setBusy(true); setError(''); setNotice(''); setCatalog(undefined); clearDerived();
    try {
      const result = await fetchCatalog();
      if (run === generation.current) setCatalog(result);
    } catch (_) {
      if (run === generation.current) setError('Catalog unavailable or permission denied.');
    } finally {
      running.current = false;
      if (run === generation.current) setBusy(false);
    }
  }
  async function mutate(operation: 'add' | 'revoke' | 'record-sighting' | 'withdraw-sighting', payload: object, changed: number) {
    if (!catalog || running.current) return;
    const expected = catalog.revision, run = ++generation.current;
    running.current = true; setBusy(true); setError(''); setNotice(''); setCatalog(undefined); clearDerived();
    try {
      const receipt = await getHttp().post<{ revision: number; changed: number }>(ROOT + operation,
        { body: JSON.stringify({ expected_revision: expected, ...payload }) });
      validateMutation(receipt, expected, changed);
      const next = await fetchCatalog();
      if (next.revision < receipt.revision) throw new Error('Stale reload');
      if (run === generation.current) {
        setCatalog(next); setNotice('Catalog change committed. Reloaded revision ' + next.revision + '.');
        setValue(''); setStix('');
      }
    } catch (_) {
      if (run === generation.current) setError('Change could not be confirmed. Reload the catalog before attempting another write. Do not retry automatically.');
    } finally {
      running.current = false;
      if (run === generation.current) setBusy(false);
    }
  }
  function add(items: IndicatorInput[]) {
    const wire = items.map(({ external_id, ...row }) => ({ ...row, ...(external_id === null ? {} : { external_id }) }));
    void mutate('add', { indicators: wire }, items.length);
  }
  let manual: IndicatorInput | undefined;
  try {
    if (/^(0|[1-9][0-9]{0,2})$/.test(confidence)) manual = validateIndicator({ type, value, source,
      confidence: Number(confidence), tlp, external_id: null, ...dates });
  } catch (_) { /* invalid form */ }
  const locked = busy || !catalog;
  const rows = (catalog?.indicators ?? []).filter(row => (filter === 'all' || row.state === filter) &&
    (!search.trim() || (row.value + ' ' + row.source + ' ' + row.type).toLowerCase().includes(search.trim().toLowerCase())));
  const chosen = catalog?.indicators.find(row => row.id === selected);
  const canAdd = !!catalog && catalog.indicators.length < 200;
  const columns: Array<EuiBasicTableColumn<Indicator>> = [
    { field: 'type', name: 'Type' }, { field: 'value', name: 'Indicator' }, { field: 'state', name: 'State at read' },
    { field: 'confidence', name: 'Confidence' }, { field: 'tlp', name: 'TLP' }, { field: 'source', name: 'Source' },
    { field: 'valid_until', name: 'Valid until (UTC)' },
    { name: 'Details', render: (row: Indicator) => <EuiButtonEmpty disabled={locked} onClick={() => {
      setSelected(row.id); setReason(''); setHunt(undefined); setExported(''); setSightingAt(''); setSightingSource(''); setSightingCount(''); setWithdrawRevision(undefined); setWithdrawReason('');
    }}>Inspect indicator</EuiButtonEmpty> },
  ];
  const batchRows = rows.filter(row => row.type === batchType && row.state === 'active');
  function prepareBatch(field: HuntField) {
    if (!batchRows.length || batchRows.length > 20) return;
    const until = Math.min(Date.now(), ...batchRows.map(row => Date.parse(row.valid_until)));
    const from = Math.max(until - DAY, ...batchRows.map(row => Date.parse(row.valid_from)));
    if (from >= until) { setError('No common elapsed validity window for the selected indicators.'); return; }
    setSelected(''); setExported('');
    setHunt({ id: 'batch', field, values: batchRows.map(row => row.value), from: new Date(from).toISOString(), until: new Date(until).toISOString() });
  }
  async function prepareExport(row: Indicator) {
    if (!catalog || running.current) return;
    const expected = catalog.revision, run = ++generation.current;
    running.current = true; setBusy(true); setExported(''); setError('');
    try {
      const fresh = await fetchCatalog();
      if (run !== generation.current) return;
      setCatalog(fresh);
      const current = fresh.indicators.find(item => item.id === row.id);
      if (fresh.revision !== expected || !current) { clearDerived(); throw new Error('Catalog changed'); }
      setExported(JSON.stringify(exportStix([current], bundleUuid(), new Date().toISOString()), null, 2));
    } catch (_) {
      if (run === generation.current) setError('Export unavailable, changed or no longer eligible. Reload before retrying.');
    } finally {
      running.current = false;
      if (run === generation.current) setBusy(false);
    }
  }
  function prepare(row: Indicator, field: HuntField) {
    const until = Math.min(Date.now(), Date.parse(row.valid_until), row.revoked_at ? Date.parse(row.revoked_at) : Infinity);
    const from = Math.max(Date.parse(row.valid_from), until - DAY);
    if (from >= until) { setError('No elapsed validity window available for this indicator.'); return; }
    setHunt({ id: row.id, field, value: row.value, from: new Date(from).toISOString(), until: new Date(until).toISOString() });
  }
  return <>
    <EuiButtonEmpty disabled={busy} onClick={back}>Back to incidents</EuiButtonEmpty>
    <EuiTitle size='l'><h1>Threat intelligence catalog</h1></EuiTitle>
    <EuiText size='s'>Shared analyst-authored indicators, not validated malicious verdicts. TLP labels are handling metadata, not per-record access controls. Do not enter secrets or source-restricted finding data. No feed fetch, external enrichment or automated response.</EuiText>
    <EuiSpacer size='s' />
    <EuiButton disabled={busy} onClick={() => void reload()}>Reload catalog</EuiButton>
    {error && <EuiCallOut color='warning' title={error} />}
    {notice && <EuiCallOut color='success' title={notice} />}
    {catalog && <>
      <EuiText size='s'>Revision {catalog.revision} · {catalog.indicators.length}/200 lifetime records · observed {catalog.observed_at}</EuiText>
      <EuiText size='s'>{['active', 'pending', 'expired', 'revoked'].map(state => state + ': ' + catalog.indicators.filter(row => row.state === state).length).join(' · ')}</EuiText>
      <EuiFormRow label='Indicator state'><EuiSelect value={filter} options={['all', 'active', 'pending', 'expired', 'revoked'].map(v => ({ value: v, text: v }))}
        onChange={e => { setFilter(e.target.value); setSelected(''); setHunt(undefined); setExported(''); }} /></EuiFormRow>
      <EuiFormRow label='Filter catalog'><EuiFieldText value={search} maxLength={256} onChange={e => { setSearch(e.target.value); setSelected(''); setHunt(undefined); setExported(''); }} /></EuiFormRow>
      <EuiBasicTable<Indicator> items={rows} columns={columns} itemId='id' noItemsMessage='No indicators in this view' />
      {chosen && <>
        <EuiSpacer size='m' /><EuiTitle size='s'><h2>Indicator details</h2></EuiTitle>
        <EuiText size='s'>ID: {chosen.id} · source: {chosen.source} · external ID: {chosen.external_id || 'None'}</EuiText>
        <EuiText size='s'>Created by {chosen.created_by} at {chosen.created_at} (revision {chosen.created_revision}). Valid from {chosen.valid_from} until {chosen.valid_until}.</EuiText>
        {chosen.revoked_at && <EuiText size='s'>Revoked by {chosen.revoked_by} at {chosen.revoked_at} (revision {chosen.revoked_revision}): {chosen.revocation_reason}</EuiText>}
        <EuiText size='s'>Prepare a historical search of an elapsed portion of this indicator's validity window. The hunt is manual and exact; no historical finding is automatically classified as malicious.</EuiText>
        {huntFields(chosen.type).map(field => <EuiButtonEmpty key={field} disabled={locked} onClick={() => prepare(chosen, field)}>Prepare hunt: {field}</EuiButtonEmpty>)}
        {chosen.state === 'active' && chosen.tlp === 'TLP:CLEAR' && <EuiButtonEmpty disabled={locked} onClick={() => void prepareExport(chosen)}>Prepare local STIX export (CLEAR only)</EuiButtonEmpty>}
        {exported && <><EuiFormRow label='Local STIX bundle' helpText='Unmarked STIX subset, no original provenance or source metadata. Review before any external sharing.'>
          <EuiTextArea value={exported} readOnly rows={10} /></EuiFormRow><EuiButtonEmpty onClick={() => setExported('')}>Clear export</EuiButtonEmpty></>}
        <EuiSpacer size='m' />
        <EuiTitle size='s'><h3>External sighting attestations</h3></EuiTitle>
        <EuiText size='s'>Analyst-entered external reports only. These are not independently verified findings, and must not contain restricted telemetry or raw evidence. Up to 10 lifetime attestations per indicator, 500 across the catalog.</EuiText>
        {chosen.sightings.map(sight => <React.Fragment key={sight.revision}>
          <EuiText size='s'>Observed {sight.observed_at} · {sight.count} reported observation(s) · {sight.source} · recorded by {sight.recorded_by} at {sight.recorded_at} (revision {sight.revision})</EuiText>
          {sight.withdrawn_at ? <EuiText size='s'>Withdrawn by {sight.withdrawn_by} at {sight.withdrawn_at}: {sight.withdrawal_reason}</EuiText> :
            <EuiButtonEmpty disabled={locked} onClick={() => { setWithdrawRevision(sight.revision); setWithdrawReason(''); }}>Prepare withdrawal</EuiButtonEmpty>}
        </React.Fragment>)}
        {withdrawRevision !== undefined && <>
          <EuiFormRow label={'Withdrawal reason for sighting revision ' + withdrawRevision}><EuiFieldText value={withdrawReason} maxLength={1024} disabled={locked} onChange={e => setWithdrawReason(e.target.value)} /></EuiFormRow>
          <EuiButton color='danger' disabled={locked || !withdrawReason.trim()} onClick={() => void mutate('withdraw-sighting',
            { id: chosen.id, sighting_revision: withdrawRevision, reason: withdrawReason.trim() }, 1)}>Confirm sighting withdrawal</EuiButton>
          <EuiButtonEmpty onClick={() => setWithdrawRevision(undefined)}>Cancel withdrawal</EuiButtonEmpty>
        </>}
        <EuiFormRow label='Externally reported observation timestamp (UTC)'><EuiFieldText value={sightingAt} maxLength={24} disabled={locked} onChange={e => setSightingAt(e.target.value)} /></EuiFormRow>
        <EuiFormRow label='External sighting source label'><EuiFieldText value={sightingSource} maxLength={256} disabled={locked} onChange={e => setSightingSource(e.target.value)} /></EuiFormRow>
        <EuiFormRow label='Externally reported observation count'><EuiFieldText value={sightingCount} maxLength={7} disabled={locked} onChange={e => setSightingCount(e.target.value)} /></EuiFormRow>
        <EuiButton disabled={locked || chosen.sightings.length >= 10 || catalog.indicators.reduce((n, row) => n + row.sightings.length, 0) >= 500 ||
            !sightingAt || !sightingSource.trim() || !/^[1-9][0-9]{0,6}$/.test(sightingCount) || Number(sightingCount) > 1000000}
          onClick={() => void mutate('record-sighting', { id: chosen.id, observed_at: sightingAt, source: sightingSource.trim(), count: Number(sightingCount) }, 1)}>Record external sighting attestation</EuiButton>
        <EuiSpacer size='m' />
        {chosen.state !== 'revoked' && <>
          <EuiFormRow label='Revocation reason'><EuiFieldText value={reason} maxLength={1024} disabled={locked} onChange={e => setReason(e.target.value)} /></EuiFormRow>
          <EuiButton color='danger' disabled={locked || !reason.trim()} onClick={() => void mutate('revoke', { id: chosen.id, reason: reason.trim() }, 1)}>Revoke indicator permanently</EuiButton>
        </>}
      </>}
      <EuiSpacer size='l' />
      <EuiTitle size='s'><h2>Active indicator matching</h2></EuiTitle>
      <EuiFormRow label='Type to match in filtered catalog'><EuiSelect value={batchType} disabled={locked} options={INDICATOR_TYPES.map(v => ({ value: v, text: v }))}
        onChange={e => { setBatchType(e.target.value as IndicatorType); setHunt(undefined); }} /></EuiFormRow>
      <EuiText size='s'>{batchRows.length} active indicators in this filtered view. Narrow filters to 1–20 indicators. The prepared hunt uses their common elapsed validity window (up to 24 hours).</EuiText>
      {huntFields(batchType).map(field => <EuiButtonEmpty key={field} disabled={locked || !batchRows.length || batchRows.length > 20}
        onClick={() => prepareBatch(field)}>Prepare batch hunt: {field}</EuiButtonEmpty>)}
      {hunt && <>
        <EuiText size='s'>Prepared indicator values and dates can be edited; results are exact telemetry matches, not persistent or verified CTI sightings.</EuiText>
        <EuiButtonEmpty onClick={() => setHunt(undefined)}>Close indicator hunt</EuiButtonEmpty>
        <IncidentHuntPanel key={JSON.stringify(hunt)} initial={hunt} disabled={locked} />
      </>}
      <EuiSpacer size='l' />
      <EuiTitle size='s'><h2>Add or renew indicator</h2></EuiTitle>
      <EuiFormRow label='Type'><EuiSelect value={type} disabled={locked} options={INDICATOR_TYPES.map(v => ({ value: v, text: v }))} onChange={e => setType(e.target.value as IndicatorType)} /></EuiFormRow>
      <EuiFormRow label='Indicator value'><EuiFieldText value={value} maxLength={253} disabled={locked} onChange={e => setValue(e.target.value)} /></EuiFormRow>
      <EuiFormRow label='Source / provenance label'><EuiFieldText value={source} maxLength={256} disabled={locked} onChange={e => { setSource(e.target.value); setPreview(undefined); }} /></EuiFormRow>
      <EuiFormRow label='Confidence (0–100)'><EuiFieldText value={confidence} maxLength={3} disabled={locked} onChange={e => setConfidence(e.target.value)} /></EuiFormRow>
      <EuiFormRow label='Handling label'><EuiSelect value={tlp} disabled={locked} options={INDICATOR_TLP.map(v => ({ value: v, text: v }))}
        onChange={e => { setTlp(e.target.value as Tlp); setPreview(undefined); }} /></EuiFormRow>
      <EuiFormRow label='Valid from (UTC)'><EuiFieldText value={dates.valid_from} maxLength={24} disabled={locked} onChange={e => setDates({ ...dates, valid_from: e.target.value })} /></EuiFormRow>
      <EuiFormRow label='Valid until (UTC)'><EuiFieldText value={dates.valid_until} maxLength={24} disabled={locked} onChange={e => setDates({ ...dates, valid_until: e.target.value })} /></EuiFormRow>
      <EuiButtonEmpty disabled={locked} onClick={() => setDates(initialDates())}>Reset validity to next 30 days</EuiButtonEmpty>
      <EuiButton disabled={locked || !manual || !canAdd} onClick={() => manual && add([manual])}>Record indicator</EuiButton>
      <EuiSpacer size='l' />
      <EuiTitle size='s'><h2>STIX 2.1 import preview</h2></EuiTitle>
      <EuiText size='s'>Up to 20 unmarked, non-revoked indicators with one supported equality pattern, explicit confidence and expiry. Marked, compound or unsupported objects are rejected, not stripped. Source and handling label come from the fields above; optional descriptive metadata is not retained. Review handling authorization before importing.</EuiText>
      <EuiFormRow label='Paste STIX JSON bundle'><EuiTextArea value={stix} maxLength={65536} rows={8} disabled={locked}
        onChange={e => { setStix(e.target.value); setPreview(undefined); }} /></EuiFormRow>
      <EuiButton disabled={locked || !stix.trim() || !source.trim()} onClick={() => {
        setError(''); setPreview(undefined);
        try { setPreview(importStix(stix, source, tlp)); } catch (_) { setError('Unsupported or malformed STIX bundle. No records prepared.'); }
      }}>Validate and preview STIX bundle</EuiButton>
      {preview && <>
        <EuiText size='s'>Prepared {preview.length} indicators · handling {tlp} · source {source}</EuiText>
        {preview.map(row => <EuiText size='s' key={row.external_id!}>{row.type}: {row.value} · confidence {row.confidence} · expires {row.valid_until}</EuiText>)}
        <EuiButton disabled={locked || catalog.indicators.length + preview.length > 200} onClick={() => add(preview)}>Confirm atomic import</EuiButton>
        <EuiButtonEmpty onClick={() => setPreview(undefined)}>Discard preview</EuiButtonEmpty>
      </>}
    </>}
  </>;
}
