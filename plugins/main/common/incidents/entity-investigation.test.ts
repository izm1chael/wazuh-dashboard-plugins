import { validateHunt, HuntReport } from './hunt-contract';
import { EntityInvestigation, RelatedIncident, validateEntityInvestigation, entityTimeline, investigationGraph, exportHuntDefinition, importHuntDefinition } from './entity-investigation';
import { validateHuntBookmarks } from './hunt-bookmark-validation';
import type { CollaborationPage, HuntBookmark } from './contracts';
const id='00000000-0000-4000-8000-000000000001', id2='00000000-0000-4000-8000-000000000002';
const input=validateHunt({field:'source.ip',values:['192.0.2.1','192.0.2.2'],from:'2026-11-25T00:00:00Z',until:'2026-11-26T00:00:00Z'});
const a={index:'.ds-wazuh-findings-v5-security-000001',document_id:'same'},b={index:'.ds-wazuh-findings-v5-security-000002',document_id:'same'};
const hunt:HuntReport={...input,scope:'caller_visible_findings_exact_terms',rows:[{...a,timestamp:input.from,matched_values:input.values},{...b,timestamp:'2026-11-25T23:59:59.999Z',matched_values:[input.values[1]]}],match_count:2};
const ca:RelatedIncident={id,revision:3,status:'active',severity:'high',matches:[a,b]},cb:RelatedIncident={id:id2,revision:5,status:'closed',severity:'medium',matches:[b]};
const report:EntityInvestigation={scope:'caller_visible_hunt_shared_case_links',hunt,cases:[ca,cb],case_count:2};
const zero:EntityInvestigation={...report,hunt:{...hunt,rows:[],match_count:0},cases:[],case_count:0};
describe('entity investigation',()=>{
  it('validates exact visible reference joins and rejects malformed case coverage',()=>{
    expect(()=>validateEntityInvestigation(report,input)).not.toThrow();
    for(const patch of [{case_count:3},{cases:[ca,ca]},{cases:[cb,ca]},{cases:[{...ca,matches:[a,a]},cb]},
      {cases:[{...ca,matches:[{...a,index:b.index,document_id:'wrong'}]},cb]},{cases:[{...ca,matches:[]},cb]},
      {cases:[{...ca,title:'secret'},cb]},{cases:[{...ca,revision:0},cb]},{scope:'wrong'}])
      expect(()=>validateEntityInvestigation({...report,...patch} as EntityInvestigation,input)).toThrow();
    expect(()=>validateEntityInvestigation(zero,input)).not.toThrow();
  });
  it('conserves distinct findings and exact graph relationships',()=>{
    const buckets=entityTimeline(hunt);
    expect(buckets.length).toBe(24);expect(buckets[0].count).toBe(1);expect(buckets[23].count).toBe(1);
    expect(buckets.reduce((s,r)=>s+r.count,0)).toBe(2);
    expect(entityTimeline(hunt,input.values[0]).reduce((s,r)=>s+r.count,0)).toBe(1);
    expect(entityTimeline(zero.hunt).reduce((s,r)=>s+r.count,0)).toBe(0);
    expect(()=>entityTimeline(hunt,'192.0.2.3')).toThrow();
    const graph=investigationGraph(report);
    expect(graph.nodes.length).toBe(6);expect(graph.edges.length).toBe(6);
    expect(new Set(graph.nodes.map(n=>n.id)).size).toBe(6);
    expect(investigationGraph(report,input.values[0]).nodes.length).toBe(3);
    expect(investigationGraph(report,input.values[0]).edges.length).toBe(2);
    expect(()=>investigationGraph(report,'unknown')).toThrow();
    expect(investigationGraph(zero).edges.length).toBe(0);
  });
  it('round trips only the portable query definition',()=>{
    expect(importHuntDefinition(exportHuntDefinition(input))).toEqual(input);
    for(const raw of ['{}',JSON.stringify({format:'wazuh-exact-hunt-v1',query:{...input,rows:[]}}),'x'.repeat(16385),
      JSON.stringify({format:'wazuh-exact-hunt-v1',query:{...input,field:'secret'}})])
      expect(()=>importHuntDefinition(raw)).toThrow();
  });
});
describe('hunt bookmarks',()=>{
  const bm:HuntBookmark={id:id+':2',label:'Pivot',query:input,created_by:'analyst',created_at:input.until,state:'saved',
    withdrawn_by:null,withdrawn_at:null,withdrawal_reason:null,withdrawn_revision:null};
  const page:CollaborationPage={observed_revision:5,hunt_bookmarks:[bm],notes:[],tasks:[],activity_pending:false};
  it('validates canonical bookmark history and rejects invalid mutations',()=>{
    expect(()=>validateHuntBookmarks(page,id)).not.toThrow();
    expect(()=>validateHuntBookmarks({...page,hunt_bookmarks:undefined},id)).not.toThrow();
    for(const patch of [{id:id2+':2'},{id:id+':6'},{label:' '},{query:{...input,values:[...input.values].reverse()}},
      {query:{...input,rows:[]}},{withdrawn_revision:3},{state:'unknown'},{created_at:'2026-02-30T12:00:00Z'}])
      expect(()=>validateHuntBookmarks({...page,hunt_bookmarks:[{...bm,...patch} as HuntBookmark]},id)).toThrow();
    expect(()=>validateHuntBookmarks({...page,hunt_bookmarks:[bm,{...bm,id:id+':3'}]},id)).toThrow();
    const withdrawn:HuntBookmark={...bm,state:'withdrawn',withdrawn_by:'analyst',withdrawn_at:'2026-11-26T00:01:00Z',withdrawal_reason:'Superseded',withdrawn_revision:3};
    expect(()=>validateHuntBookmarks({...page,hunt_bookmarks:[withdrawn,{...bm,id:id+':4'}]},id)).not.toThrow();
    expect(()=>validateHuntBookmarks({...page,hunt_bookmarks:[{...withdrawn,withdrawn_revision:2}]},id)).toThrow();
    expect(()=>validateHuntBookmarks({...page,hunt_bookmarks:[withdrawn,{...bm,id:id+':3'}]},id)).toThrow();
    expect(()=>validateHuntBookmarks({...page,hunt_bookmarks:[{...withdrawn,withdrawn_at:'2026-11-25T00:00:00Z'}]},id)).toThrow();
  });
});
