import type { CollaborationPage } from './contracts';
import { validateHunt } from './hunt-contract';
const text=(v:unknown,max:number):v is string=>typeof v==='string' && v.length<=max && !!v.trim() && v===v.trim() && !/[\x00-\x1f\x7f-\x9f]/.test(v);
const date=(v:unknown):v is string=>typeof v==='string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/.test(v) && Number.isFinite(Date.parse(v)) && new Date(v).toISOString().slice(0,19)===v.slice(0,19);
const exact=(v:object,keys:string[])=>Object.keys(v).length===keys.length && keys.every(k=>Object.prototype.hasOwnProperty.call(v,k));
const fail=():never=>{throw new Error('Invalid hunt bookmark history');};
export function validateHuntBookmarks(page:CollaborationPage,id:string):void {
  if(page.hunt_bookmarks===undefined) return;
  const rows=page.hunt_bookmarks;
  if(!Array.isArray(rows)||rows.length>20) return fail();
  let prior=0; const revisions=new Set<number>(),active=new Set<string>();
  for(const row of rows) {
    if(!row||!exact(row,['id','label','query','created_by','created_at','state','withdrawn_by','withdrawn_at','withdrawal_reason','withdrawn_revision'])||
      !text(row.id,64)||!row.id.startsWith(id+':')||!text(row.label,128)||!text(row.created_by,1024)||!date(row.created_at)||
      !row.query||!exact(row.query,['field','values','from','until'])) return fail();
    const rev=Number(row.id.slice(id.length+1));
    if(!Number.isSafeInteger(rev)||rev<=prior||rev>page.observed_revision||row.id!==id+':'+rev||revisions.has(rev)) return fail();
    revisions.add(rev); prior=rev;
    const query=validateHunt(row.query);
    if(JSON.stringify(query.values)!==JSON.stringify(row.query.values)) return fail();
    const key=JSON.stringify(query);
    if(row.state==='saved') {
      if(active.has(key)||row.withdrawn_by!==null||row.withdrawn_at!==null||row.withdrawal_reason!==null||row.withdrawn_revision!==null) return fail();
      active.add(key);
    } else if(row.state==='withdrawn') {
      const end=row.withdrawn_revision;
      if(typeof end!=='number'||!Number.isSafeInteger(end)||end<=rev||end>page.observed_revision||revisions.has(end)||
        !text(row.withdrawn_by,1024)||!date(row.withdrawn_at)||Date.parse(row.withdrawn_at)<Date.parse(row.created_at)||!text(row.withdrawal_reason,1024)) return fail();
      revisions.add(end);
    } else return fail();
  }
}
