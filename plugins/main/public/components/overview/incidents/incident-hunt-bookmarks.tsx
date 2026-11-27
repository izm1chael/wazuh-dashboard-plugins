import React, { useState } from 'react';
import { EuiButtonEmpty, EuiCallOut, EuiFormRow, EuiPanel, EuiSpacer, EuiText, EuiTextArea, EuiTitle } from '@elastic/eui';
import type { HuntBookmark, IndexerIncidentCommand } from '../../../../common/incidents/contracts';
import { IncidentHuntPanel } from './incident-hunt-panel';

export function IncidentHuntBookmarks({ bookmarks, disabled, command, openRelated }: {
  bookmarks: HuntBookmark[]; disabled: boolean; command: (value: IndexerIncidentCommand)=>Promise<void>; openRelated?: (id:string)=>void;
}) {
  const [selected,setSelected]=useState('');
  const [newQuery,setNewQuery]=useState(false);
  const [reason,setReason]=useState('');
  const current=bookmarks.find(row=>row.id===selected && row.state==='saved');
  return <>
    <EuiTitle size='s'><h2>Case hunt bookmarks</h2></EuiTitle>
    <EuiText size='s'>Saved definitions only, not search results or evidence. Shared with authorized case readers. Withdrawal retains the original query in history. Rerunning always checks current source permissions.</EuiText>
    <EuiSpacer size='s' />
    <EuiText size='s'>{bookmarks.length} of 20 lifetime bookmarks.</EuiText>
    <EuiButtonEmpty disabled={disabled || bookmarks.length>=20} onClick={()=>{setSelected('');setNewQuery(value=>!value);}}>{newQuery?'Close new hunt':'Prepare new case hunt'}</EuiButtonEmpty>
    {newQuery && <IncidentHuntPanel disabled={disabled} attach={command} saveBookmark={command} openRelated={openRelated} />}
    {bookmarks.map(row=><EuiPanel key={row.id} paddingSize='s' hasShadow={false} hasBorder>
      <EuiText size='s'><strong>{row.label}</strong> · {row.state} · {row.created_by} · {row.created_at}
        <p>{row.query.field} · {row.query.values.join(', ')} · {row.query.from} to {row.query.until}</p>
        {row.state==='withdrawn' && <p>Withdrawn by {row.withdrawn_by} · {row.withdrawn_at} · {row.withdrawal_reason}</p>}
      </EuiText>
      {row.state==='saved' && <EuiButtonEmpty disabled={disabled} onClick={()=>{setSelected(row.id);setReason('');setNewQuery(false);}}>Load saved query</EuiButtonEmpty>}
    </EuiPanel>)}
    {current && <>
      <EuiSpacer size='s' />
      <EuiCallOut title='Loaded bookmark'>Review the exact historical bounds before running. Loading does not search.</EuiCallOut>
      <EuiButtonEmpty onClick={()=>setSelected('')}>Close loaded query</EuiButtonEmpty>
      <IncidentHuntPanel key={current.id} initial={current.query} disabled={disabled} attach={command} openRelated={openRelated} />
      <EuiFormRow label='Withdraw bookmark reason'><EuiTextArea value={reason} maxLength={1024} disabled={disabled} onChange={e=>setReason(e.target.value)} /></EuiFormRow>
      <EuiButtonEmpty disabled={disabled || !reason.trim() || reason!==reason.trim() || /[\x00-\x1f\x7f-\x9f]/.test(reason)}
        onClick={()=>void command({kind:'withdraw-hunt-bookmark',bookmark_id:current.id,reason})}>Withdraw saved query</EuiButtonEmpty>
    </>}
    <EuiSpacer size='m' />
  </>;
}
