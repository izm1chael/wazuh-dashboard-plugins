/** Local native replay receipt review. Imported receipts and labels are operator assertions, not signed authorization. */
export interface ReplayRow {index:string;id:string;source_sha256:string;baseline:string[];candidate:string[];gained:string[];lost:string[]}
export interface ReplayScope {integration:string;cluster:string;space:string;dataset:string;from:string;until:string}
export interface NativeReplayReceipt {
  format:'wazuh-native-paired-replay-v1';scope:ReplayScope;observed_at:string;test_sha256:string;custom_sha256:string;
  preview_sha256:string;event_count:number;baseline_matches:number;candidate_matches:number;gained_matches:number;lost_matches:number;
  rows:ReplayRow[];coverage:'exact_search_telemetry_unverified';promotion_authorized:false
}
export interface ReplayLabel {index:string;id:string;source_sha256:string;truth:'positive'|'negative'|'unknown';partition:'tuning'|'holdout'}
export interface ReplayLabels {format:'wazuh-native-replay-labels-v1';rule_uuid:string;labels:ReplayLabel[]}
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const SHA=/^[a-f0-9]{64}$/;
const INDEX=/^(?:\.ds-)?wazuh-events-v5-[a-z0-9][a-z0-9-]*-[0-9]{6}$/;
const exact=(v:object,k:string[])=>Object.keys(v).length===k.length&&k.every(key=>Object.prototype.hasOwnProperty.call(v,key));
const safe=(v:unknown,max=256):v is string=>typeof v==='string'&&v.length<=max&&v.trim()===v&&!!v&&!/[\x00-\x1f\x7f-\x9f]/.test(v);
const fail=():never=>{throw new Error('Invalid native replay review input');};
const uuid=(v:unknown):v is string=>typeof v==='string'&&UUID.test(v);
const hash=(v:unknown):v is string=>typeof v==='string'&&SHA.test(v);
const time=(v:unknown):v is string=>typeof v==='string'&&/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|\+00:00)$/.test(v)&&Number.isFinite(Date.parse(v))&&new Date(v).toISOString().slice(0,19)===v.slice(0,19);
const key=(r:{index:string;id:string})=>JSON.stringify([r.index,r.id]);
function ids(raw:string[]):string[]{
  if(!Array.isArray(raw)||raw.length>200||raw.some((v,i)=>!uuid(v)||(i>0&&raw[i-1]>=v)))return fail();
  return raw;
}
function equal(a:string[],b:string[]){return a.length===b.length&&a.every((v,i)=>v===b[i]);}
export function validateNativeReplay(raw:NativeReplayReceipt):NativeReplayReceipt {
  if(!raw||!exact(raw,['format','scope','observed_at','test_sha256','custom_sha256','preview_sha256','event_count','baseline_matches','candidate_matches','gained_matches','lost_matches','rows','coverage','promotion_authorized'])||
    raw.format!=='wazuh-native-paired-replay-v1'||raw.coverage!=='exact_search_telemetry_unverified'||raw.promotion_authorized!==false||
    !hash(raw.test_sha256)||!hash(raw.custom_sha256)||!hash(raw.preview_sha256)||!time(raw.observed_at)||
    !raw.scope||!exact(raw.scope,['integration','cluster','space','dataset','from','until'])||
    !uuid(raw.scope.integration)||![raw.scope.cluster,raw.scope.space,raw.scope.dataset].every(v=>safe(v))||
    !time(raw.scope.from)||!time(raw.scope.until)||Date.parse(raw.scope.until)<=Date.parse(raw.scope.from)||
    Date.parse(raw.scope.until)-Date.parse(raw.scope.from)>86400000||Date.parse(raw.observed_at)<Date.parse(raw.scope.until)+120000||
    !Array.isArray(raw.rows)||!raw.rows.length||raw.rows.length>100||raw.event_count!==raw.rows.length)return fail();
  const seen=new Set<string>();let base=0,candidate=0,gained=0,lost=0;
  for(const row of raw.rows){
    if(!row||!exact(row,['index','id','source_sha256','baseline','candidate','gained','lost'])||
      !safe(row.index,255)||!INDEX.test(row.index)||!safe(row.id,512)||!hash(row.source_sha256)||seen.has(key(row)))return fail();
    seen.add(key(row));
    const b=ids(row.baseline),c=ids(row.candidate),g=ids(row.gained),l=ids(row.lost);
    if(!equal(g,c.filter(v=>!b.includes(v)))||!equal(l,b.filter(v=>!c.includes(v))))return fail();
    base+=b.length;candidate+=c.length;gained+=g.length;lost+=l.length;
  }
  if(raw.baseline_matches!==base||raw.candidate_matches!==candidate||raw.gained_matches!==gained||raw.lost_matches!==lost)return fail();
  return raw;
}
export function parseNativeReplay(raw:string):NativeReplayReceipt{
  if(typeof raw!=='string'||raw.length>8000000)return fail();
  return validateNativeReplay(JSON.parse(raw));
}
export function validateReplayLabels(raw:ReplayLabels,receipt:NativeReplayReceipt):ReplayLabels {
  validateNativeReplay(receipt);
  if(!raw||!exact(raw,['format','rule_uuid','labels'])||raw.format!=='wazuh-native-replay-labels-v1'||!uuid(raw.rule_uuid)||
    !Array.isArray(raw.labels)||raw.labels.length!==receipt.rows.length)return fail();
  const source=new Map(receipt.rows.map(row=>[key(row),row.source_sha256])),seen=new Set<string>();
  for(const row of raw.labels){
    if(!row||!exact(row,['index','id','source_sha256','truth','partition'])||!safe(row.index,255)||!safe(row.id,512)||
      !hash(row.source_sha256)||source.get(key(row))!==row.source_sha256||seen.has(key(row))||
      !['positive','negative','unknown'].includes(row.truth)||!['tuning','holdout'].includes(row.partition))return fail();
    seen.add(key(row));
  }
  return raw;
}
export interface Confusion {tp:number;fp:number;tn:number;fn:number}
export interface PairedReview {baseline:Confusion;candidate:Confusion;positives:number;negatives:number;unknown:number;
  lost_positives:number;gained_positives:number;new_false_positives:number;removed_false_positives:number;
  partition:'tuning'|'holdout';status:'insufficient_labels'|'regression'|'no_improvement'|'review_candidate'}
export function pairedReview(receipt:NativeReplayReceipt,labels:ReplayLabels,partition:'tuning'|'holdout'):PairedReview{
  validateReplayLabels(labels,receipt);
  const map=new Map(receipt.rows.map(row=>[key(row),row]));
  const baseline={tp:0,fp:0,tn:0,fn:0},candidate={tp:0,fp:0,tn:0,fn:0};
  let positives=0,negatives=0,unknown=0,lost_positives=0,gained_positives=0,new_false_positives=0,removed_false_positives=0;
  for(const label of labels.labels){
    if(label.partition!==partition)continue;
    const row=map.get(key(label))!;
    const b=row.baseline.includes(labels.rule_uuid),c=row.candidate.includes(labels.rule_uuid);
    if(label.truth==='unknown'){unknown++;continue;}
    if(label.truth==='positive'){
      positives++;baseline[b?'tp':'fn']++;candidate[c?'tp':'fn']++;
      if(b&&!c)lost_positives++;if(!b&&c)gained_positives++;
    }else{
      negatives++;baseline[b?'fp':'tn']++;candidate[c?'fp':'tn']++;
      if(!b&&c)new_false_positives++;if(b&&!c)removed_false_positives++;
    }
  }
  const status=positives<10||negatives<10||unknown>0?'insufficient_labels':
    lost_positives||new_false_positives?'regression':!gained_positives&&!removed_false_positives?'no_improvement':'review_candidate';
  return {baseline,candidate,positives,negatives,unknown,lost_positives,gained_positives,new_false_positives,removed_false_positives,partition,status};
}
