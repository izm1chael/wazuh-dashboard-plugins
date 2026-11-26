import React, { useEffect, useRef, useState } from 'react';
import { EuiButtonEmpty, EuiCallOut, EuiSpacer, EuiText } from '@elastic/eui';
import type { EvidenceArtifact } from '../../../../common/incidents/contracts';

const MAX_BYTES = 32 * 1024 * 1024;

/** A browser-only comparison; neither file bytes nor its computed digest are sent to an API. */
export function LocalEvidenceVerifier({ evidence, onBusy }: { evidence: EvidenceArtifact; onBusy: (busy: boolean) => void }) {
  const [active, setActive] = useState(false);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<'match' | 'mismatch' | 'unavailable' | 'too_large'>();
  const generation = useRef(0);
  const working = useRef(false);
  useEffect(() => () => { generation.current++; }, []);

  async function verify(file?: File) {
    if (!file || working.current) return;
    setResult(undefined);
    if (file.size > MAX_BYTES) { setResult('too_large'); return; }
    if (!window.crypto?.subtle) { setResult('unavailable'); return; }
    const run = ++generation.current;
    working.current = true; setBusy(true); onBusy(true);
    try {
      const bytes = await file.arrayBuffer();
      if (generation.current !== run) return;
      const digest = await window.crypto.subtle.digest('SHA-256', bytes);
      const hex = Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, '0')).join('');
      if (generation.current === run) setResult(hex === evidence.sha256 ? 'match' : 'mismatch');
    } catch (_) {
      if (generation.current === run) setResult('unavailable');
    } finally {
      working.current = false;
      if (generation.current === run) { setBusy(false); onBusy(false); }
    }
  }

  if (!active) return <EuiButtonEmpty onClick={() => setActive(true)}>Compare local file hash</EuiButtonEmpty>;
  return <>
    <EuiSpacer size='s' />
    <EuiText size='s'>Choose a local file up to 32 MiB. Only a browser-side SHA-256 comparison is performed; nothing is uploaded or saved and this does not establish custody or authenticity.</EuiText>
    <input type='file' aria-label={'Compare file for ' + evidence.label} disabled={busy} onChange={e => {
      const file = e.target.files?.[0]; e.target.value = ''; void verify(file);
    }} />
    <EuiButtonEmpty disabled={busy} onClick={() => { setActive(false); setResult(undefined); }}>Clear local comparison</EuiButtonEmpty>
    {busy && <EuiText size='s'>Calculating locally…</EuiText>}
    {result === 'match' && <EuiCallOut color='success' title='Selected file matches the attested SHA-256' />}
    {result === 'mismatch' && <EuiCallOut color='danger' title='Selected file does not match the attested SHA-256' />}
    {result === 'too_large' && <EuiCallOut color='warning' title='File exceeds local 32 MiB comparison limit'>Use your separately controlled forensic tooling for larger files.</EuiCallOut>}
    {result === 'unavailable' && <EuiCallOut color='warning' title='Local comparison unavailable'>A supported secure browser context is required.</EuiCallOut>}
  </>;
}
