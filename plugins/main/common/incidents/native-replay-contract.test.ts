import { NativeReplayReceipt, ReplayLabels, ReplayRow, validateNativeReplay, validateReplayLabels, pairedReview, parseNativeReplay } from './native-replay-contract';
const A='00000000-0000-4000-8000-000000000001',B='00000000-0000-4000-8000-000000000002';
const index='.ds-wazuh-events-v5-access-management-000001',hash='a'.repeat(64);
function row(i:number,baseline:string[],candidate:string[]):ReplayRow{return {index,id:String(i),source_sha256:hash,baseline,candidate,gained:candidate.filter(x=>!baseline.includes(x)),lost:baseline.filter(x=>!candidate.includes(x))};}
function receipt(rows:ReplayRow[]):NativeReplayReceipt{return {format:'wazuh-native-paired-replay-v1',scope:{integration:A,cluster:'lab',space:'standard',dataset:'sshd',from:'2026-11-25T00:00:00Z',until:'2026-11-25T00:05:00Z'},observed_at:'2026-11-25T00:07:00+00:00',test_sha256:hash,custom_sha256:hash,preview_sha256:hash,event_count:rows.length,baseline_matches:rows.reduce((s,r)=>s+r.baseline.length,0),candidate_matches:rows.reduce((s,r)=>s+r.candidate.length,0),gained_matches:rows.reduce((s,r)=>s+r.gained.length,0),lost_matches:rows.reduce((s,r)=>s+r.lost.length,0),rows,coverage:'exact_search_telemetry_unverified',promotion_authorized:false};}
function labels(r:NativeReplayReceipt):ReplayLabels{return {format:'wazuh-native-replay-labels-v1',rule_uuid:A,labels:r.rows.map((x,i)=>({index:x.index,id:x.id,source_sha256:x.source_sha256,truth:i<10?'positive':'negative',partition:'holdout'}))};}
describe('native replay receipts',()=>{
  it('validates exact match differences and rejects invalid identities',()=>{
    const r=receipt([row(0,[A],[B])]);
    expect(parseNativeReplay(JSON.stringify(r))).toEqual(r);
    expect(validateNativeReplay(receipt([]))).toEqual(receipt([]));
    expect(()=>validateNativeReplay({...r,event_count:2})).toThrow();
    expect(()=>validateNativeReplay({...r,lost_matches:0})).toThrow();
    expect(()=>validateNativeReplay(receipt([row(0,[A],[B]),row(0,[A],[B])]))).toThrow();
    expect(()=>validateNativeReplay(receipt([row(0,[A,A],[B])]))).toThrow();
    expect(()=>validateNativeReplay({...r,rows:[{...r.rows[0],gained:[]}]})).toThrow();
    expect(()=>validateNativeReplay({...r,promotion_authorized:true} as unknown as NativeReplayReceipt)).toThrow();
  });
  it('compares labelled holdout without counting unknowns as negatives',()=>{
    const r=receipt(Array.from({length:20},(_,i)=>row(i,[A],i<10?[A]:[])));
    const l=labels(r),review=pairedReview(r,l,'holdout');
    expect(review.baseline).toEqual({tp:10,fp:10,tn:0,fn:0});
    expect(review.candidate).toEqual({tp:10,fp:0,tn:10,fn:0});
    expect(review.removed_false_positives).toBe(10);
    expect(review.status).toBe('review_candidate');
    expect(pairedReview(r,l,'tuning').status).toBe('insufficient_labels');
    expect(pairedReview(r,{...l,labels:[{...l.labels[0],truth:'unknown'},...l.labels.slice(1)]},'holdout').status).toBe('insufficient_labels');
    expect(()=>validateReplayLabels({...l,labels:[{...l.labels[0],source_sha256:'b'.repeat(64)},...l.labels.slice(1)]},r)).toThrow();
    expect(()=>validateReplayLabels({...l,labels:l.labels.slice(1)},r)).toThrow();
    const regression=receipt([row(0,[A],[]),...r.rows.slice(1)]);
    expect(pairedReview(regression,labels(regression),'holdout').status).toBe('regression');
    expect(pairedReview(regression,labels(regression),'holdout').lost_positives).toBe(1);
  });
});
