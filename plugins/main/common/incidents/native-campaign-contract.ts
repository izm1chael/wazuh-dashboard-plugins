/** Aggregate evidence pack validation. A local import is not authenticated release authorization. */
export interface CampaignMetrics {
  positive:number;negative:number;unknown:number;lost_positive:number;gained_positive:number;
  new_false_positive:number;removed_false_positive:number;baseline_tp:number;baseline_fp:number;baseline_tn:number;
  baseline_fn:number;candidate_tp:number;candidate_fp:number;candidate_tn:number;candidate_fn:number;
}
export interface CampaignPack {
  format:'wazuh-native-rule-review-pack-v1';status:'blocked'|'ready_for_independent_release_review';
  blockers:string[];scope:{integration:string;cluster:string;space:string;dataset:string};changed_rules:string[];
  test_sha256:string;custom_sha256:string;preview_sha256:string;review_plan_sha256:string;
  historical_receipt_sha256:string[];prospective_receipt_sha256:string[];labels_sha256:string;
  review_attestation:{author:string;reviewer:string;review_plan_sha256:string;reason:string};
  registered_epoch:number;prospective_windows:number;prospective_seconds:number;historical_events:number;prospective_events:number;
  historical_metrics:Record<string,CampaignMetrics>;prospective_metrics:Record<string,CampaignMetrics>;
  coverage:'exact_search_telemetry_unverified';promotion_authorized:false;
}
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const SHA=/^[a-f0-9]{64}$/;
const exact=(v:object,k:string[])=>Object.keys(v).length===k.length&&k.every(key=>Object.prototype.hasOwnProperty.call(v,key));
const text=(v:unknown,max:number):v is string=>typeof v==='string'&&v.length<=max&&v===v.trim()&&!!v&&!/[\x00-\x1f\x7f-\x9f]/.test(v);
const hash=(v:unknown):v is string=>typeof v==='string'&&SHA.test(v);
const int=(v:unknown,min=0,max=30000):v is number=>typeof v==='number'&&Number.isSafeInteger(v)&&v>=min&&v<=max;
const fail=():never=>{throw new Error('Invalid campaign review pack');};
const metricKeys=['positive','negative','unknown','lost_positive','gained_positive','new_false_positive','removed_false_positive',
  'baseline_tp','baseline_fp','baseline_tn','baseline_fn','candidate_tp','candidate_fp','candidate_tn','candidate_fn'];
function metrics(m:CampaignMetrics,population:number){
  if(!m||!exact(m,metricKeys)||!Object.values(m).every(v=>int(v,0,population))||
    m.positive+m.negative+m.unknown!==population||
    m.baseline_tp+m.baseline_fn!==m.positive||m.candidate_tp+m.candidate_fn!==m.positive||
    m.baseline_tn+m.baseline_fp!==m.negative||m.candidate_tn+m.candidate_fp!==m.negative||
    m.lost_positive>Math.min(m.baseline_tp,m.candidate_fn)||m.gained_positive>Math.min(m.baseline_fn,m.candidate_tp)||
    m.new_false_positive>Math.min(m.baseline_tn,m.candidate_fp)||m.removed_false_positive>Math.min(m.baseline_fp,m.candidate_tn)||
    m.candidate_tp!==m.baseline_tp+m.gained_positive-m.lost_positive||
    m.candidate_fp!==m.baseline_fp+m.new_false_positive-m.removed_false_positive)return fail();
}
function hashes(v:string[],minimum:number){
  if(!Array.isArray(v)||v.length<minimum||v.length>288||!v.every(hash)||new Set(v).size!==v.length)return fail();
}
export function validateCampaignPack(pack:CampaignPack):CampaignPack{
  if(!pack||!exact(pack,['format','status','blockers','scope','changed_rules','test_sha256','custom_sha256','preview_sha256',
    'review_plan_sha256','historical_receipt_sha256','prospective_receipt_sha256','labels_sha256','review_attestation','registered_epoch',
    'prospective_windows','prospective_seconds','historical_events','prospective_events','historical_metrics','prospective_metrics','coverage','promotion_authorized'])||
    pack.format!=='wazuh-native-rule-review-pack-v1'||pack.coverage!=='exact_search_telemetry_unverified'||pack.promotion_authorized!==false||
    ![pack.test_sha256,pack.custom_sha256,pack.preview_sha256,pack.review_plan_sha256,pack.labels_sha256].every(hash)||
    !pack.scope||!exact(pack.scope,['integration','cluster','space','dataset'])||!UUID.test(pack.scope.integration)||
    ![pack.scope.cluster,pack.scope.space,pack.scope.dataset].every(v=>text(v,256))||
    !Array.isArray(pack.changed_rules)||!pack.changed_rules.length||pack.changed_rules.length>20||
    pack.changed_rules.some((v,i)=>typeof v!=='string'||!UUID.test(v)||(i>0&&v<=pack.changed_rules[i-1])))return fail();
  hashes(pack.historical_receipt_sha256,1);hashes(pack.prospective_receipt_sha256,1);
  if(new Set([...pack.historical_receipt_sha256,...pack.prospective_receipt_sha256]).size!==pack.historical_receipt_sha256.length+pack.prospective_receipt_sha256.length||
    !int(pack.registered_epoch,0,Number.MAX_SAFE_INTEGER)||!int(pack.prospective_windows,1,288)||
    pack.prospective_windows!==pack.prospective_receipt_sha256.length||
    !int(pack.prospective_seconds,300,288*3600)||pack.prospective_seconds%pack.prospective_windows||
    !int(pack.historical_events,0,pack.historical_receipt_sha256.length*100)||
    !int(pack.prospective_events,0,pack.prospective_windows*100)||pack.historical_events+pack.prospective_events>30000)return fail();
  const width=pack.prospective_seconds/pack.prospective_windows;
  if(!int(width,300,3600)||86400%width)return fail();
  const a=pack.review_attestation;
  if(!a||!exact(a,['author','reviewer','review_plan_sha256','reason'])||
    ![a.author,a.reviewer,a.reason].every(v=>text(v,1024))||a.author===a.reviewer||a.review_plan_sha256!==pack.review_plan_sha256||
    !pack.historical_metrics||!pack.prospective_metrics||!exact(pack.historical_metrics,pack.changed_rules)||
    !exact(pack.prospective_metrics,pack.changed_rules))return fail();
  const blockers:string[]=[];
  if(pack.prospective_seconds<86400)blockers.push('prospective_duration_under_24h');
  for(const rule of pack.changed_rules){
    const h=pack.historical_metrics[rule],p=pack.prospective_metrics[rule];
    metrics(h,pack.historical_events);metrics(p,pack.prospective_events);
    for(const [name,m] of [['historical',h],['prospective',p]] as const){
      if(m.positive<10||m.negative<10||m.unknown)blockers.push(rule+':'+name+':insufficient_labels');
      if(m.lost_positive||m.new_false_positive)blockers.push(rule+':'+name+':regression');
    }
    if(!h.gained_positive&&!h.removed_false_positive)blockers.push(rule+':historical:no_improvement');
  }
  if(!Array.isArray(pack.blockers)||JSON.stringify(pack.blockers)!==JSON.stringify(blockers)||
    pack.status!==(blockers.length?'blocked':'ready_for_independent_release_review'))return fail();
  return pack;
}
export function parseCampaignPack(raw:string):CampaignPack{
  if(typeof raw!=='string'||raw.length>500000)return fail();
  return validateCampaignPack(JSON.parse(raw));
}
