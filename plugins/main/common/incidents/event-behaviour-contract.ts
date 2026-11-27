import { assessRuleVolume, RuleVolumeAssessment } from './rule-behaviour-contract';

export const EVENT_MODES=['authentication','process','network'] as const;
export type EventMode=typeof EVENT_MODES[number];
export interface EventProfileInput {mode:EventMode;cluster:string;space:string;dataset:string;subject:string;day:string}
export interface EventRelationships {baseline_distinct:number;comparison_distinct:number;baseline_missing:number;comparison_missing:number;
  newly_observed:Array<{value:string;count:number}>}
export interface EventCoverage {status:'search_complete_telemetry_unverified';active_baseline_days:number;ingest_lag_known:number;
  ingest_lag_missing:number;ingest_before_event:number;ingest_after_observation:number;lag_over_120s:number;max_lag_seconds:number}
export interface EventProfile {
  scope:'caller_visible_native_event_profile';model:'event_profile_v1';query:EventProfileInput;observed_at:string;actor:string;event_count:number;
  volume:RuleVolumeAssessment;authentication:null|{success:RuleVolumeAssessment;failure:RuleVolumeAssessment;unknown:RuleVolumeAssessment};
  relationship:EventRelationships;source_relationship:EventRelationships|null;coverage:EventCoverage;
}
const DAY=86400000;
const fail=():never=>{throw new Error('Invalid native event profile');};
const exact=(v:object,k:string[])=>Object.keys(v).length===k.length&&k.every(key=>Object.prototype.hasOwnProperty.call(v,key));
const text=(v:unknown,max=256):v is string=>typeof v==='string'&&v.length<=max&&v.trim()===v&&!!v&&!/[\x00-\x1f\x7f-\x9f]/.test(v);
const instant=(v:unknown):v is string=>typeof v==='string'&&/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/.test(v)&&Number.isFinite(Date.parse(v))&&new Date(v).toISOString().slice(0,19)===v.slice(0,19);
const integer=(n:unknown,min=0,max=2000):n is number=>typeof n==='number'&&Number.isSafeInteger(n)&&n>=min&&n<=max;
const ipv4=(v:string)=>v.split('.').length===4&&v.split('.').every(p=>/^(0|[1-9][0-9]{0,2})$/.test(p)&&Number(p)<=255);
export function validateEventProfileInput(input:EventProfileInput,now=Date.now()):EventProfileInput{
  if(!input||!exact(input,['mode','cluster','space','dataset','subject','day'])||!EVENT_MODES.includes(input.mode)||
    ![input.cluster,input.space,input.dataset,input.subject].every(v=>text(v))||!instant(input.day))return fail();
  const day=Date.parse(input.day);
  if(day%DAY||day<Date.UTC(2000,0,29)||day+DAY>=Date.UTC(2100,0,1)||day+DAY>now-120000||
    input.day!==new Date(day).toISOString().replace('.000Z','Z'))return fail();
  return input;
}
function volume(row:RuleVolumeAssessment):RuleVolumeAssessment{
  if(!row)return fail();
  const expected=assessRuleVolume(row.daily_counts,row.current_count);
  if(!exact(row,Object.keys(expected))||Object.keys(expected).some(k=>JSON.stringify(expected[k as keyof RuleVolumeAssessment])!==JSON.stringify(row[k as keyof RuleVolumeAssessment])))return fail();
  return expected;
}
function relations(row:EventRelationships,baseline:number,current:number,ip:boolean){
  if(!row||!exact(row,['baseline_distinct','comparison_distinct','baseline_missing','comparison_missing','newly_observed'])||
    !integer(row.baseline_missing,0,baseline)||!integer(row.comparison_missing,0,current)||
    !integer(row.baseline_distinct,0,Math.min(100,baseline-row.baseline_missing))||
    !integer(row.comparison_distinct,0,Math.min(100,current-row.comparison_missing))||
    (row.baseline_distinct===0)!==(baseline===row.baseline_missing)||
    (row.comparison_distinct===0)!==(current===row.comparison_missing)||
    !Array.isArray(row.newly_observed)||row.newly_observed.length>row.comparison_distinct||
    row.newly_observed.length<Math.max(0,row.comparison_distinct-row.baseline_distinct))return fail();
  let prior='',novelCount=0;
  for(const item of row.newly_observed){
    if(!item||!exact(item,['value','count'])||!text(item.value)||(ip&&!ipv4(item.value))||item.value<=prior||!integer(item.count,1,current))return fail();
    prior=item.value;novelCount+=item.count;
  }
  if(novelCount+row.comparison_distinct-row.newly_observed.length>current-row.comparison_missing)return fail();
  if(row.comparison_distinct===row.newly_observed.length&&novelCount!==current-row.comparison_missing)return fail();
}
export function validateEventProfile(profile:EventProfile,input:EventProfileInput):EventProfile{
  if(!profile||!exact(profile,['scope','model','query','observed_at','actor','event_count','volume','authentication','relationship','source_relationship','coverage'])||
    profile.scope!=='caller_visible_native_event_profile'||profile.model!=='event_profile_v1'||!instant(profile.observed_at)||!text(profile.actor,1024)||
    !profile.query||!exact(profile.query,Object.keys(input))||Object.keys(input).some(k=>profile.query[k as keyof EventProfileInput]!==input[k as keyof EventProfileInput]))return fail();
  validateEventProfileInput(input,Date.parse(profile.observed_at));
  const v=volume(profile.volume);
  if(profile.event_count!==v.baseline_total+v.current_count)return fail();
  if(input.mode==='authentication'){
    const a=profile.authentication;
    if(!a||!exact(a,['success','failure','unknown'])||!profile.source_relationship)return fail();
    const channels=[volume(a.success),volume(a.failure),volume(a.unknown)];
    if(channels.reduce((s,r)=>s+r.current_count,0)!==v.current_count||
      v.daily_counts.some((n,i)=>channels.reduce((s,r)=>s+r.daily_counts[i],0)!==n))return fail();
    relations(profile.source_relationship,v.baseline_total,v.current_count,true);
  }else if(profile.authentication!==null||profile.source_relationship!==null)return fail();
  relations(profile.relationship,v.baseline_total,v.current_count,input.mode==='network');
  const c=profile.coverage;
  if(!c||!exact(c,['status','active_baseline_days','ingest_lag_known','ingest_lag_missing','ingest_before_event','ingest_after_observation','lag_over_120s','max_lag_seconds'])||
    c.status!=='search_complete_telemetry_unverified'||c.active_baseline_days!==v.active_days||
    ![c.ingest_lag_known,c.ingest_lag_missing,c.ingest_before_event,c.ingest_after_observation].every(n=>integer(n))||
    c.ingest_lag_known+c.ingest_lag_missing+c.ingest_before_event+c.ingest_after_observation!==profile.event_count||
    !integer(c.lag_over_120s,0,c.ingest_lag_known)||!integer(c.max_lag_seconds,0,Number.MAX_SAFE_INTEGER)||
    (!c.ingest_lag_known&&c.max_lag_seconds!==0)||(c.lag_over_120s>0)!==(c.max_lag_seconds>120))return fail();
  return profile;
}
