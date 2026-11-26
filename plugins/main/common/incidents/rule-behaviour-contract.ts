import { BEHAVIOUR_FIELDS, BehaviourField } from './behaviour-contract';
import { validHuntValue } from './hunt-contract';

export const RULE_VOLUME_MAX=2000;
const DAY=86400000;
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const INDEX=/^(?:\.ds-)?wazuh-findings-v5-[a-z0-9][a-z0-9-]*-[0-9]{6}$/;
const fail=():never=>{throw new Error('Invalid bounded rule behaviour report');};
const exact=(v:object,keys:string[])=>Object.keys(v).length===keys.length&&keys.every(k=>Object.prototype.hasOwnProperty.call(v,k));
const safe=(v:unknown,max:number):v is string=>typeof v==='string'&&v.length<=max&&!!v.trim()&&!/[\x00-\x1f\x7f-\x9f]/.test(v);
const time=(v:unknown):v is string=>typeof v==='string'&&/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/.test(v)&&Number.isFinite(Date.parse(v))&&new Date(v).toISOString().slice(0,19)===v.slice(0,19);
const canonicalDay=(ms:number)=>new Date(ms).toISOString().replace('.000Z','Z');

export interface RuleBehaviourInput { field:BehaviourField; value:string; rule_uuid:string; day:string }
export type RuleVolumeClass='no_observed_activity'|'newly_observed'|'sparse_baseline'|'elevated_rule_volume'|'within_volume_threshold';
export interface RuleVolumeAssessment {
  daily_counts:number[]; baseline_total:number; active_days:number; same_weekday_maximum:number;
  median_times_two:number; mad_times_four:number; threshold:number; current_count:number; classification:RuleVolumeClass;
}
export interface RuleBehaviourReport {
  scope:'caller_visible_rule_finding_scan';model:'rule_volume_v2';query:RuleBehaviourInput;
  baseline_from:string;until:string;finding_count:number;assessment:RuleVolumeAssessment;
  current_sample:Array<{index:string;document_id:string;timestamp:string}>;
  coverage:'search_complete_telemetry_unverified';actor:string;observed_at:string;
}

export function validateRuleBehaviour(input:RuleBehaviourInput,now=Date.now()):RuleBehaviourInput {
  if(!input||!exact(input,['field','value','rule_uuid','day'])||!BEHAVIOUR_FIELDS.includes(input.field)||
    !validHuntValue(input.field,input.value)||typeof input.rule_uuid!=='string'||!UUID.test(input.rule_uuid)||
    !time(input.day))return fail();
  const day=Date.parse(input.day);
  if(day%DAY||day<Date.UTC(2000,0,29)||day+DAY>=Date.UTC(2100,0,1)||day+DAY>now-120000||
    input.day!==canonicalDay(day))return fail();
  return {field:input.field,value:input.value,rule_uuid:input.rule_uuid,day:input.day};
}
export function assessRuleVolume(daily:number[],current:number):RuleVolumeAssessment {
  if(!Array.isArray(daily)||daily.length!==28||daily.some(n=>!Number.isInteger(n)||n<0||n>RULE_VOLUME_MAX)||
    !Number.isInteger(current)||current<0||current>RULE_VOLUME_MAX)return fail();
  const total=daily.reduce((a,b)=>a+b,0),active=daily.filter(n=>n>0).length;
  if(total+current>RULE_VOLUME_MAX)return fail();
  const weekdayMax=Math.max(...daily.filter((_,i)=>i%7===0));
  const sorted=[...daily].sort((a,b)=>a-b),median2=sorted[13]+sorted[14];
  const deviations=sorted.map(n=>Math.abs(2*n-median2)).sort((a,b)=>a-b),mad4=deviations[13]+deviations[14];
  const threshold=Math.max(5,weekdayMax+3,Math.ceil(2*total/28),Math.ceil((2*median2+3*mad4)/4));
  const classification:RuleVolumeClass=total===0?(current===0?'no_observed_activity':'newly_observed'):
    active<7?'sparse_baseline':current>=threshold?'elevated_rule_volume':'within_volume_threshold';
  return {daily_counts:[...daily],baseline_total:total,active_days:active,same_weekday_maximum:weekdayMax,
    median_times_two:median2,mad_times_four:mad4,threshold,current_count:current,classification};
}
export function validateRuleBehaviourReport(report:RuleBehaviourReport,input:RuleBehaviourInput):RuleBehaviourReport {
  if(!report||!exact(report,['scope','model','query','baseline_from','until','finding_count','assessment','current_sample','coverage','actor','observed_at'])||
    report.scope!=='caller_visible_rule_finding_scan'||report.model!=='rule_volume_v2'||report.coverage!=='search_complete_telemetry_unverified'||
    !report.query||!exact(report.query,Object.keys(input))||Object.keys(input).some(k=>report.query[k as keyof RuleBehaviourInput]!==input[k as keyof RuleBehaviourInput])||
    report.baseline_from!==canonicalDay(Date.parse(input.day)-28*DAY)||report.until!==canonicalDay(Date.parse(input.day)+DAY)||
    !safe(report.actor,1024)||!time(report.observed_at)||Date.parse(report.observed_at)<Date.parse(report.until)+120000||
    !report.assessment||!Array.isArray(report.current_sample))return fail();
  const expected=assessRuleVolume(report.assessment.daily_counts,report.assessment.current_count);
  if(!exact(report.assessment,Object.keys(expected))||Object.keys(expected).some(k=>
    JSON.stringify(report.assessment[k as keyof RuleVolumeAssessment])!==JSON.stringify(expected[k as keyof RuleVolumeAssessment]))||
    report.finding_count!==expected.baseline_total+expected.current_count||
    report.current_sample.length!==Math.min(20,expected.current_count))return fail();
  const seen=new Set<string>();
  for(const row of report.current_sample){
    if(!row||!exact(row,['index','document_id','timestamp'])||!safe(row.index,255)||!INDEX.test(row.index)||
      !safe(row.document_id,512)||!time(row.timestamp)||Date.parse(row.timestamp)<Date.parse(input.day)||
      Date.parse(row.timestamp)>=Date.parse(report.until))return fail();
    const key=JSON.stringify([row.index,row.document_id]);if(seen.has(key))return fail();seen.add(key);
  }
  return report;
}
