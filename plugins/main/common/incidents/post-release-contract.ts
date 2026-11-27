import { DetectionRelease, releaseHash, validateRelease } from './detection-release-contract';
export interface VolumeReceipt {count:number;population_sha256:string}
export interface FindingVolumeReceipt extends VolumeReceipt {by_rule:Record<string,number>}
export interface ContentReconciliation {
  test_snapshot_sha256:string;custom_snapshot_sha256:string;integration_document_equal:boolean;all_integration_rule_documents_equal:boolean;
  reviewed_rules:Array<{rule_uuid:string;expected_document_sha256:string;actual_document_sha256:string;equal:boolean}>;
}
export interface PostReleaseReview {
  format:'wazuh-native-post-release-review-v1';plan_sha256:string;pack_sha256:string;
  scope:{integration:string;cluster:string;space:string;dataset:string};observed_at:string;native_status:number;
  reserved_at:string;native_reported_at:string;windows:{baseline_from:string;baseline_until:string;post_from:string;post_until:string};
  content:ContentReconciliation;
  baseline:{events:VolumeReceipt;findings:FindingVolumeReceipt};post:{events:VolumeReceipt;findings:FindingVolumeReceipt};
  rules:Array<{rule_uuid:string;baseline_findings:number;post_findings:number;delta:number;
    classification:'no_observed_post_findings'|'higher_observed_volume'|'lower_observed_volume'|'same_observed_volume'}>;
  coverage:'exact_search_telemetry_unverified';deployment_verified:false;automatic_rollback_authorized:false;
}
const exact=(v:object,k:string[])=>Object.keys(v).length===k.length&&k.every(key=>Object.prototype.hasOwnProperty.call(v,key));
const time=(v:unknown):v is string=>typeof v==='string'&&/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|\+00:00)$/.test(v)&&Number.isFinite(Date.parse(v))&&new Date(v).toISOString().slice(0,19)===v.slice(0,19);
const integer=(n:unknown):n is number=>typeof n==='number'&&Number.isSafeInteger(n)&&n>=0&&n<=2000;
const fail=():never=>{throw new Error('Invalid post-release review');};
export function validatePostReleaseReview(report:PostReleaseReview,release:DetectionRelease):PostReleaseReview{
  validateRelease(release);
  if(!report||!exact(report,['format','plan_sha256','pack_sha256','scope','observed_at','native_status','reserved_at','native_reported_at','windows',
    'content','baseline','post','rules','coverage','deployment_verified','automatic_rollback_authorized'])||
    report.format!=='wazuh-native-post-release-review-v1'||report.coverage!=='exact_search_telemetry_unverified'||
    report.deployment_verified!==false||report.automatic_rollback_authorized!==false||release.state!=='native_reported'||
    report.plan_sha256!==release.id||report.pack_sha256!==release.evidence.pack_sha256||
    report.native_status!==release.outcome?.native_status||![200,202].includes(report.native_status)||
    report.reserved_at!==release.reservation?.at||report.native_reported_at!==release.outcome?.at||
    !report.scope||!exact(report.scope,['integration','cluster','space','dataset'])||
    !(['integration','cluster','space','dataset'] as const).every(k=>report.scope[k]===release.evidence[k])||!time(report.observed_at))return fail();
  const w=report.windows;
  if(!w||!exact(w,['baseline_from','baseline_until','post_from','post_until'])||
    !Object.values(w).every(v=>time(v)&&v.length===20&&v.endsWith('Z')))return fail();
  const [a,b,c,d]=[w.baseline_from,w.baseline_until,w.post_from,w.post_until].map(v=>Date.parse(v));
  const now=Date.parse(report.observed_at);
  if(b<=a||b-a>86400000||d-c!==b-a||b>c||b>Date.parse(report.reserved_at)||c<Date.parse(report.native_reported_at)||
    d>now-120000||a<now-30*86400000)return fail();
  const rules=release.evidence.changed_rules;
  const content=report.content;
  if(!content||!exact(content,['test_snapshot_sha256','custom_snapshot_sha256','integration_document_equal','all_integration_rule_documents_equal','reviewed_rules'])||
    content.test_snapshot_sha256!==release.evidence.test_sha256||typeof content.integration_document_equal!=='boolean'||
    typeof content.all_integration_rule_documents_equal!=='boolean'||!Array.isArray(content.reviewed_rules)||content.reviewed_rules.length!==rules.length)return fail();
  releaseHash(content.custom_snapshot_sha256);
  content.reviewed_rules.forEach((r,i)=>{
    if(!r||!exact(r,['rule_uuid','expected_document_sha256','actual_document_sha256','equal'])||r.rule_uuid!==rules[i]||
      r.equal!==(releaseHash(r.expected_document_sha256)===releaseHash(r.actual_document_sha256))||
      (content.all_integration_rule_documents_equal&&!r.equal))return fail();
  });
  for(const v of [report.baseline,report.post]){
    if(!v||!exact(v,['events','findings'])||!v.events||!exact(v.events,['count','population_sha256'])||!integer(v.events.count)||
      !v.findings||!exact(v.findings,['count','population_sha256','by_rule'])||!integer(v.findings.count)||
      !v.findings.by_rule||!exact(v.findings.by_rule,rules)||!Object.values(v.findings.by_rule).every(integer)||
      Object.values(v.findings.by_rule).reduce((a,b)=>a+b,0)!==v.findings.count)return fail();
    releaseHash(v.events.population_sha256);releaseHash(v.findings.population_sha256);
  }
  if(!Array.isArray(report.rules)||report.rules.length!==rules.length)return fail();
  report.rules.forEach((r,i)=>{
    const rule=rules[i],before=report.baseline.findings.by_rule[rule],after=report.post.findings.by_rule[rule];
    const expected=!after?'no_observed_post_findings':after>before?'higher_observed_volume':after<before?'lower_observed_volume':'same_observed_volume';
    if(!r||!exact(r,['rule_uuid','baseline_findings','post_findings','delta','classification'])||r.rule_uuid!==rule||
      r.baseline_findings!==before||r.post_findings!==after||r.delta!==after-before||r.classification!==expected)return fail();
  });
  return report;
}
export function parsePostReleaseReview(raw:string,release:DetectionRelease):PostReleaseReview{
  if(typeof raw!=='string'||raw.length>100000)return fail();
  return validatePostReleaseReview(JSON.parse(raw),release);
}
