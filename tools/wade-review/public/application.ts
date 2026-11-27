// SPDX-License-Identifier: AGPL-3.0-or-later
import { parseCohort, reviewCohort } from './review';

/** Offline import only. Never uploads telemetry, mutates rules or stores imported files. */
export function renderWorkspace(element: HTMLElement): () => void {
  const root = document.createElement('section');
  root.style.cssText = 'max-width:1100px;margin:24px auto;padding:16px;line-height:1.5';
  const add = (parent: HTMLElement, tag: string, text: string) => {
    const e = document.createElement(tag); e.textContent = text; parent.appendChild(e); return e;
  };
  add(root,'h1','WADE Detection Engineering');
  add(root,'p','Offline replay review — import a paired, labelled cohort. Imported evidence is not authenticated, and no rule can be promoted from this workspace.');
  const label = add(root,'label','Replay cohort JSON (maximum 8 MiB)');
  const input = document.createElement('input'); input.type='file'; input.accept='.json,application/json'; input.style.display='block'; label.appendChild(input);
  const status=add(root,'p','No cohort loaded.'); status.setAttribute('role','status');
  const results=document.createElement('div'); root.appendChild(results); element.appendChild(root);
  let generation=0; let mounted=true;
  const change=async () => {
    const token=++generation; results.replaceChildren(); status.textContent='No cohort loaded.';
    const file=input.files?.[0]; if(!file)return;
    if(file.size>8*1024*1024){status.textContent='Import exceeds 8 MiB.';return;}
    try {
      const cohort=parseCohort(await file.text());
      if(!mounted||token!==generation)return;
      const review=reviewCohort(cohort); status.textContent=review.status==='REVIEW_CANDIDATE'?'Review candidate — independent human approval still required.':'Withheld — quality gate failed.';
      add(results,'h2','Paired replay results');
      add(results,'p','Champion: '+cohort.champion_digest); add(results,'p','Challenger: '+cohort.challenger_digest);
      const table=document.createElement('table'); table.style.cssText='width:100%;text-align:left;border-collapse:collapse'; results.appendChild(table);
      const caption=document.createElement('caption'); caption.textContent='Imported cohort summary'; table.appendChild(caption);
      const values: [string,number][]=[['Benign cases',review.benign],['Malicious cases',review.malicious],['Unlabelled cases',review.unlabelled],['Incomplete paired outcomes',review.unknown],['Champion false positives',review.false_positives_before],['Challenger false positives',review.false_positives_after],['Malicious regressions',review.malicious_regressions.length],['Protected-case failures',review.protected_failures.length]];
      for(const [name,value] of values){const row=table.insertRow();const header=document.createElement('th');header.scope='row';header.textContent=name;row.appendChild(header);row.insertCell().textContent=String(value);}
      add(results,'h2','Review gates'); const reasons=document.createElement('ul');results.appendChild(reasons);
      for(const reason of review.reasons.length?review.reasons:['All local paired-outcome checks passed; provenance and approval still required.'])add(reasons,'li',reason);
      for(const [title,ids] of [['Malicious regression cases',review.malicious_regressions],['Protected-case failures',review.protected_failures]] as [string,string[]][]){
        if(!ids.length)continue;add(results,'h3',title);const list=document.createElement('ul');results.appendChild(list);for(const id of ids.slice(0,100))add(list,'li',id);if(ids.length>100)add(results,'p',`${ids.length-100} more cases not displayed.`);
      }
    }catch(_error){if(mounted&&token===generation){results.replaceChildren();status.textContent='Invalid or unsupported cohort. Check the WADE import contract.';}}
  };
  input.addEventListener('change',change);
  return () => {mounted=false;generation++;input.removeEventListener('change',change);root.remove();};
}
