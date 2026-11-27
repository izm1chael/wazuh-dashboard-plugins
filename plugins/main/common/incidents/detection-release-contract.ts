import { CampaignMetrics, CampaignPack, metrics, validateCampaignPack } from './native-campaign-contract';

export interface ReleaseEvidence {
  pack_sha256:string;test_sha256:string;custom_sha256:string;preview_sha256:string;labels_sha256:string;
  integration:string;cluster:string;space:string;dataset:string;changed_rules:string[];
  historical_events:number;prospective_events:number;prospective_seconds:number;
  historical_metrics:Record<string,CampaignMetrics>;prospective_metrics:Record<string,CampaignMetrics>;
}
export interface ReleaseReview {actor:string;at:string;decision:'approved'|'rejected';reason:string;pack_sha256:string;deployer:string|null;expires:string|null}
export interface DetectionRelease {
  format:'wazuh-detection-release-v1';id:string;evidence:ReleaseEvidence;author:string;submitted_at:string;
  state:'submitted'|'approved'|'rejected'|'reserved'|'native_reported';revision:number;review:ReleaseReview|null;
  reservation:{actor:string;at:string}|null;outcome:{at:string;native_status:number}|null;
}
export interface ReleaseDay {scope:'shared_detection_release_metadata';day:string;rows:DetectionRelease[];count:number}
export interface ReleaseReviewInput {id:string;pack_json:string;decision:'approved'|'rejected';reason:string;deployer:string|null;expires:string|null}
const HASH=/^[a-f0-9]{64}$/;
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const exact=(v:object,k:string[])=>Object.keys(v).length===k.length&&k.every(key=>Object.prototype.hasOwnProperty.call(v,key));
const safe=(v:unknown,max=1024):v is string=>typeof v==='string'&&v.length<=max&&v.trim()===v&&!!v&&!/[\x00-\x1f\x7f-\x9f]/.test(v);
const actor=(v:unknown):v is string=>safe(v)&&v!=='_shared';
const time=(v:unknown):v is string=>typeof v==='string'&&/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/.test(v)&&Number.isFinite(Date.parse(v))&&new Date(v).toISOString().slice(0,19)===v.slice(0,19);
const integer=(n:unknown,min:number,max:number):n is number=>typeof n==='number'&&Number.isSafeInteger(n)&&n>=min&&n<=max;
const fail=():never=>{throw new Error('Invalid detection release');};
export function releaseHash(v:unknown):string{if(typeof v!=='string'||!HASH.test(v))return fail();return v;}
export function validateReleaseEvidence(e:ReleaseEvidence):ReleaseEvidence{
  if(!e||!exact(e,['pack_sha256','test_sha256','custom_sha256','preview_sha256','labels_sha256','integration','cluster','space','dataset','changed_rules',
    'historical_events','prospective_events','prospective_seconds','historical_metrics','prospective_metrics'])||
    !safe(e.integration,36)||!UUID.test(e.integration)||![e.cluster,e.space,e.dataset].every(v=>safe(v,256))||
    !Array.isArray(e.changed_rules)||!e.changed_rules.length||e.changed_rules.length>20||
    e.changed_rules.some((v,i)=>!safe(v,36)||!UUID.test(v)||(i>0&&v<=e.changed_rules[i-1]))||
    !integer(e.historical_events,0,30000)||!integer(e.prospective_events,0,30000)||e.historical_events+e.prospective_events>30000||
    !integer(e.prospective_seconds,86400,288*3600)||!e.historical_metrics||!e.prospective_metrics||
    !exact(e.historical_metrics,e.changed_rules)||!exact(e.prospective_metrics,e.changed_rules))return fail();
  [e.pack_sha256,e.test_sha256,e.custom_sha256,e.preview_sha256,e.labels_sha256].forEach(releaseHash);
  for(const rule of e.changed_rules){
    const h=e.historical_metrics[rule],p=e.prospective_metrics[rule];
    metrics(h,e.historical_events);metrics(p,e.prospective_events);
    if([h,p].some(m=>m.positive<10||m.negative<10||m.unknown||m.lost_positive||m.new_false_positive)||
      (!h.gained_positive&&!h.removed_false_positive))return fail();
  }
  return e;
}
export function evidenceFromPack(pack:CampaignPack,packHash:string):ReleaseEvidence{
  validateCampaignPack(pack);
  if(pack.status!=='ready_for_independent_release_review'||pack.blockers.length)return fail();
  return validateReleaseEvidence({pack_sha256:releaseHash(packHash),test_sha256:pack.test_sha256,custom_sha256:pack.custom_sha256,
    preview_sha256:pack.preview_sha256,labels_sha256:pack.labels_sha256,...pack.scope,changed_rules:pack.changed_rules,
    historical_events:pack.historical_events,prospective_events:pack.prospective_events,prospective_seconds:pack.prospective_seconds,
    historical_metrics:pack.historical_metrics,prospective_metrics:pack.prospective_metrics});
}
function stable(v:unknown):string{
  if(Array.isArray(v))return '['+v.map(stable).join(',')+']';
  if(v!==null&&typeof v==='object'){
    const m=v as Record<string,unknown>;
    return '{'+Object.keys(m).sort().map(k=>JSON.stringify(k)+':'+stable(m[k])).join(',')+'}';
  }
  return JSON.stringify(v);
}
export const sameReleaseEvidence=(a:ReleaseEvidence,b:ReleaseEvidence)=>stable(validateReleaseEvidence(a))===stable(validateReleaseEvidence(b));
export function validateRelease(row:DetectionRelease):DetectionRelease{
  if(!row||!exact(row,['format','id','evidence','author','submitted_at','state','revision','review','reservation','outcome'])||
    row.format!=='wazuh-detection-release-v1'||!actor(row.author)||!time(row.submitted_at))return fail();
  releaseHash(row.id);validateReleaseEvidence(row.evidence);
  if(row.revision===1&&row.state==='submitted'&&row.review===null&&row.reservation===null&&row.outcome===null)return row;
  const r=row.review;
  if(!r||!exact(r,['actor','at','decision','reason','pack_sha256','deployer','expires'])||!actor(r.actor)||r.actor===row.author||
    !time(r.at)||Date.parse(r.at)<Date.parse(row.submitted_at)||!safe(r.reason)||r.pack_sha256!==row.evidence.pack_sha256)return fail();
  if(r.decision==='rejected'){
    if(row.revision===2&&row.state==='rejected'&&r.deployer===null&&r.expires===null&&row.reservation===null&&row.outcome===null)return row;
    return fail();
  }
  if(r.decision!=='approved'||!actor(r.deployer)||r.deployer===row.author||r.deployer===r.actor||!time(r.expires)||
    r.expires.length!==20||Date.parse(r.expires)<=Date.parse(r.at)||Date.parse(r.expires)>Date.parse(r.at)+3600000)return fail();
  if(row.revision===2&&row.state==='approved'&&row.reservation===null&&row.outcome===null)return row;
  const reserved=row.reservation;
  if(!reserved||!exact(reserved,['actor','at'])||reserved.actor!==r.deployer||!time(reserved.at)||
    Date.parse(reserved.at)<Date.parse(r.at)||Date.parse(reserved.at)>=Date.parse(r.expires))return fail();
  if(row.revision===3&&row.state==='reserved'&&row.outcome===null)return row;
  const outcome=row.outcome;
  if(row.revision===4&&row.state==='native_reported'&&outcome&&exact(outcome,['at','native_status'])&&time(outcome.at)&&
    Date.parse(outcome.at)>=Date.parse(reserved.at)&&integer(outcome.native_status,100,599))return row;
  return fail();
}
export function validateReleaseDay(day:string,now=Date.now()):string{
  if(!time(day)||day.length!==20||Date.parse(day)%86400000||Date.parse(day)<Date.UTC(2000,0,1)||Date.parse(day)>now)return fail();
  return day;
}
export function validateReleasePage(page:ReleaseDay,day:string):ReleaseDay{
  if(!page||!exact(page,['scope','day','rows','count'])||page.scope!=='shared_detection_release_metadata'||page.day!==day||
    !Array.isArray(page.rows)||page.rows.length>50||page.count!==page.rows.length)return fail();
  let prior='';
  for(const row of page.rows){
    validateRelease(row);
    if(row.id<=prior||Date.parse(row.submitted_at)<Date.parse(day)||Date.parse(row.submitted_at)>=Date.parse(day)+86400000)return fail();
    prior=row.id;
  }
  return page;
}
export function validateReviewInput(input:ReleaseReviewInput,now=Date.now()):ReleaseReviewInput{
  if(!input||!exact(input,['id','pack_json','decision','reason','deployer','expires'])||typeof input.pack_json!=='string'||
    !input.pack_json.length||input.pack_json.length>500000||!safe(input.reason))return fail();
  releaseHash(input.id);
  if(input.decision==='rejected'&&input.deployer===null&&input.expires===null)return input;
  if(input.decision==='approved'&&actor(input.deployer)&&time(input.expires)&&input.expires.length===20&&
    Date.parse(input.expires)>now&&Date.parse(input.expires)<=now+3600000)return input;
  return fail();
}
