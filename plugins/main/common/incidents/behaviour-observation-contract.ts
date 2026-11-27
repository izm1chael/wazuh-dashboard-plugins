import { RuleBehaviourInput, RuleVolumeAssessment, assessRuleVolume, validateRuleBehaviour } from './rule-behaviour-contract';

export const OBSERVATION_DECISIONS=['dismissed','monitor','escalation_requested'] as const;
export type ObservationDecision=typeof OBSERVATION_DECISIONS[number];
export type ObservationState='not_flagged'|'unreviewed'|ObservationDecision|'promoted';
export interface BehaviourObservation {
  id:string; model:'rule_volume_v2'; query:RuleBehaviourInput; actor:string; observed_at:string;
  coverage:'search_complete_telemetry_unverified'; finding_count:number; assessment:RuleVolumeAssessment;
  state:ObservationState; revision:number; review:null|{actor:string;at:string;decision:ObservationDecision;reason:string};
  incident_id:string|null; promoted_at:string|null;
}
export interface ObservationPage {scope:'shared_soc_observation_metadata';day:string;rows:BehaviourObservation[];count:number}
export interface ObservationReview {id:string;expected_revision:number;decision:ObservationDecision;reason:string}
export interface ObservationPromotion {id:string;expected_revision:number}
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const DAY=86400000;
const fail=():never=>{throw new Error('Invalid behaviour observation');};
const exact=(v:object,keys:string[])=>Object.keys(v).length===keys.length&&keys.every(k=>Object.prototype.hasOwnProperty.call(v,k));
const text=(v:unknown,max:number):v is string=>typeof v==='string'&&v.length<=max&&!!v.trim()&&v===v.trim()&&!/[\x00-\x1f\x7f-\x9f]/.test(v);
const time=(v:unknown):v is string=>typeof v==='string'&&/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/.test(v)&&Number.isFinite(Date.parse(v))&&new Date(v).toISOString().slice(0,19)===v.slice(0,19);
const uuid=(v:unknown):v is string=>typeof v==='string'&&UUID.test(v);
export function validateObservationDay(day:string,now=Date.now()):string {
  if(!time(day)||day!==new Date(Date.parse(day)).toISOString().replace('.000Z','Z')||Date.parse(day)%DAY||
    Date.parse(day)<Date.UTC(2000,0,29)||Date.parse(day)+DAY>now-120000||Date.parse(day)+DAY>=Date.UTC(2100,0,1))return fail();
  return day;
}
export function validateObservation(row:BehaviourObservation):BehaviourObservation {
  if(!row||!exact(row,['id','model','query','actor','observed_at','coverage','finding_count','assessment','state','revision','review','incident_id','promoted_at'])||
    !uuid(row.id)||row.model!=='rule_volume_v2'||row.coverage!=='search_complete_telemetry_unverified'||
    !text(row.actor,1024)||!time(row.observed_at)||!row.query||!row.assessment)return fail();
  validateRuleBehaviour(row.query,Date.parse(row.observed_at));
  const expected=assessRuleVolume(row.assessment.daily_counts,row.assessment.current_count);
  if(!exact(row.assessment,Object.keys(expected))||Object.keys(expected).some(k=>
    JSON.stringify(row.assessment[k as keyof RuleVolumeAssessment])!==JSON.stringify(expected[k as keyof RuleVolumeAssessment]))||
    row.finding_count!==expected.baseline_total+expected.current_count)return fail();
  const flagged=['newly_observed','elevated_rule_volume'].includes(expected.classification);
  if(row.revision===1){
    if(row.state!==(flagged?'unreviewed':'not_flagged')||row.review!==null||row.incident_id!==null||row.promoted_at!==null)return fail();
    return row;
  }
  const review=row.review;
  if(!flagged||!review||!exact(review,['actor','at','decision','reason'])||!text(review.actor,1024)||row.actor===review.actor||
    !time(review.at)||Date.parse(review.at)<Date.parse(row.observed_at)||!text(review.reason,1024)||
    !OBSERVATION_DECISIONS.includes(review.decision))return fail();
  if(row.revision===2&&row.state===review.decision&&row.incident_id===null&&row.promoted_at===null)return row;
  if(row.revision===3&&row.state==='promoted'&&review.decision==='escalation_requested'&&uuid(row.incident_id)&&
    time(row.promoted_at)&&Date.parse(row.promoted_at)>=Date.parse(review.at))return row;
  return fail();
}
const rank=(r:BehaviourObservation)=>r.state==='unreviewed'?(r.assessment.classification==='elevated_rule_volume'?0:1):
  r.state==='escalation_requested'?2:3;
export function validateObservationPage(page:ObservationPage,day:string):ObservationPage {
  if(!page||!exact(page,['scope','day','rows','count'])||page.scope!=='shared_soc_observation_metadata'||page.day!==day||
    !Array.isArray(page.rows)||page.rows.length>50||page.count!==page.rows.length)return fail();
  let previousRank=-1,previousId='';const seen=new Set<string>(),scopes=new Set<string>();
  for(const row of page.rows){
    validateObservation(row);
    const r=rank(row),scope=JSON.stringify([row.actor,row.query.field,row.query.value,row.query.rule_uuid]);
    if(row.query.day!==day||scopes.has(scope)||seen.has(row.id)||r<previousRank||(r===previousRank&&row.id<=previousId))return fail();
    seen.add(row.id);scopes.add(scope);previousRank=r;previousId=row.id;
  }
  return page;
}
export function validateObservationReview(input:ObservationReview):ObservationReview {
  if(!input||!exact(input,['id','expected_revision','decision','reason'])||!uuid(input.id)||input.expected_revision!==1||
    !OBSERVATION_DECISIONS.includes(input.decision)||!text(input.reason,1024))return fail();
  return input;
}
export function validateObservationPromotion(input:ObservationPromotion):ObservationPromotion {
  if(!input||!exact(input,['id','expected_revision'])||!uuid(input.id)||input.expected_revision!==2)return fail();
  return input;
}
export function validateReviewResult(row:BehaviourObservation,input:ObservationReview):BehaviourObservation {
  validateObservation(row);
  if(row.id!==input.id||row.revision!==2||row.state!==input.decision||row.review?.reason!==input.reason)return fail();
  return row;
}
export function validatePromotionResult(row:BehaviourObservation,input:ObservationPromotion):BehaviourObservation {
  validateObservation(row);
  if(row.id!==input.id||row.revision!==3||row.state!=='promoted')return fail();
  return row;
}

export interface EntityObservationPriority {
  key:string; publisher:string; field:RuleBehaviourInput['field']; value:string;
  observed_rules:number; elevated_rules:number; newly_observed_rules:number;
  awaiting_review:number; awaiting_promotion:number; observation_ids:string[];
}
/** Exact same publisher + field + literal only. No cross-field identity inference, finding sums or risk probability. */
export function entityObservationPriorities(page:ObservationPage):EntityObservationPriority[] {
  validateObservationPage(page,page.day);
  const groups=new Map<string,{row:EntityObservationPriority;rules:Set<string>}>();
  for(const observation of page.rows){
    const {field,value,rule_uuid}=observation.query;
    const key=JSON.stringify([observation.actor,field,value]);
    let group=groups.get(key);
    if(!group){
      group={row:{key,publisher:observation.actor,field,value,observed_rules:0,elevated_rules:0,newly_observed_rules:0,
        awaiting_review:0,awaiting_promotion:0,observation_ids:[]},rules:new Set<string>()};
      groups.set(key,group);
    }
    if(group.rules.has(rule_uuid))return fail();
    group.rules.add(rule_uuid);
    const row=group.row;
    row.observed_rules++;
    if(observation.assessment.classification==='elevated_rule_volume')row.elevated_rules++;
    if(observation.assessment.classification==='newly_observed')row.newly_observed_rules++;
    if(observation.state==='unreviewed')row.awaiting_review++;
    if(observation.state==='escalation_requested')row.awaiting_promotion++;
    row.observation_ids.push(observation.id);
  }
  return Array.from(groups.values(),g=>g.row).sort((a,b)=>b.awaiting_review-a.awaiting_review||
    b.awaiting_promotion-a.awaiting_promotion||b.elevated_rules-a.elevated_rules||
    b.newly_observed_rules-a.newly_observed_rules||(a.key<b.key?-1:a.key>b.key?1:0));
}
