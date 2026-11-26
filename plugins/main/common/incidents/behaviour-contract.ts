import { HuntInput, HuntField, HuntReport, validateHunt, validateHuntReport } from './hunt-contract';

export const BEHAVIOUR_FIELDS = ['wazuh.agent.id','host.id','host.name','host.hostname','host.ip','source.ip','destination.ip','user.name','user.id'] as const;
export type BehaviourField = typeof BEHAVIOUR_FIELDS[number];
export type Classification = 'no_observed_activity'|'newly_observed'|'sparse_baseline'|'elevated_volume'|'within_volume_threshold';
export interface BehaviourAssessment {
  value:string; daily_counts:number[]; baseline_total:number; active_days:number; baseline_maximum:number;
  threshold:number; current_count:number; classification:Classification;
}
export interface BehaviourReport {
  scope:'caller_visible_finding_volume'; model:'daily_volume_v1'; baseline:HuntReport; current:HuntReport; assessments:BehaviourAssessment[];
}
const DAY=86400000;
const fail=():never=>{throw new Error('Invalid bounded behavioural assessment');};
const exact=(v:object,keys:string[])=>Object.keys(v).length===keys.length && keys.every(k=>Object.prototype.hasOwnProperty.call(v,k));
export function validateBehaviourInput(input:HuntInput,now=Date.now()):HuntInput {
  const q=validateHunt(input);
  const from=Date.parse(q.from),until=Date.parse(q.until);
  if(!BEHAVIOUR_FIELDS.includes(q.field as BehaviourField)||q.values.length>5||from%DAY!==0||until-from!==DAY||
    until>now-120000||from-7*DAY<Date.UTC(2000,0,1)) return fail();
  return q;
}
export function baselineInput(input:HuntInput):HuntInput {
  return {...input,from:new Date(Date.parse(input.from)-7*DAY).toISOString(),until:input.from};
}
export function assessVolume(value:string,daily:number[],current:number):BehaviourAssessment {
  if(!Array.isArray(daily)||daily.length!==7||daily.some(n=>!Number.isInteger(n)||n<0||n>100)||
    !Number.isInteger(current)||current<0||current>100) return fail();
  const total=daily.reduce((a,b)=>a+b,0),active=daily.filter(n=>n>0).length,max=Math.max(...daily);
  if(total>100) return fail();
  const threshold=Math.max(5,max+3,Math.ceil(2*total/7));
  const classification:Classification=total===0?(current===0?'no_observed_activity':'newly_observed'):
    active<3?'sparse_baseline':current>=threshold?'elevated_volume':'within_volume_threshold';
  return {value,daily_counts:[...daily],baseline_total:total,active_days:active,baseline_maximum:max,
    threshold,current_count:current,classification};
}
export function validateBehaviourReport(report:BehaviourReport,input:HuntInput):BehaviourReport {
  if(!report||!exact(report,['scope','model','baseline','current','assessments'])||
    report.scope!=='caller_visible_finding_volume'||report.model!=='daily_volume_v1'||
    !Array.isArray(report.assessments)||report.assessments.length!==input.values.length) return fail();
  const baseline=validateHuntReport(report.baseline,baselineInput(input));
  const current=validateHuntReport(report.current,input);
  const seen=new Set<string>();
  for(const row of [...baseline.rows,...current.rows]){
    const key=JSON.stringify([row.index,row.document_id]);
    if(seen.has(key))return fail();
    seen.add(key);
  }
  const start=Date.parse(baseline.from);
  for(let n=0;n<input.values.length;n++){
    const value=input.values[n],daily=Array<number>(7).fill(0);
    for(const row of baseline.rows)if(row.matched_values.includes(value))daily[Math.floor((Date.parse(row.timestamp)-start)/DAY)]++;
    const expected=assessVolume(value,daily,current.rows.filter(row=>row.matched_values.includes(value)).length);
    const actual=report.assessments[n];
    if(!actual||!exact(actual,Object.keys(expected))||Object.keys(expected).some(key=>
      JSON.stringify(actual[key as keyof BehaviourAssessment])!==JSON.stringify(expected[key as keyof BehaviourAssessment])))return fail();
  }
  return report;
}
