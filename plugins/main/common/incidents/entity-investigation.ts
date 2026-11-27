import { HuntInput, HuntReport, validateHunt, validateHuntReport } from './hunt-contract';

export interface EntityReference { index: string; document_id: string }
export interface RelatedIncident { id: string; revision: number; status: 'new'|'triaging'|'active'|'closed';
  severity: 'informational'|'low'|'medium'|'high'|'critical'; matches: EntityReference[] }
export interface EntityInvestigation { scope: 'caller_visible_hunt_shared_case_links'; hunt: HuntReport; cases: RelatedIncident[]; case_count: number }
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const fail = (): never => { throw new Error('Invalid entity investigation'); };
const exact = (row: object, keys: string[]) => Object.keys(row).length === keys.length && keys.every(k => Object.prototype.hasOwnProperty.call(row,k));
export const findingKey = (row: EntityReference) => JSON.stringify([row.index,row.document_id]);

export function validateEntityInvestigation(value: EntityInvestigation, input: HuntInput): EntityInvestigation {
  if (!value || !exact(value,['scope','hunt','cases','case_count']) || value.scope !== 'caller_visible_hunt_shared_case_links' ||
      !Array.isArray(value.cases) || value.cases.length > 50 || value.case_count !== value.cases.length) return fail();
  const hunt = validateHuntReport(value.hunt,input);
  const visible = new Set(hunt.rows.map(findingKey)), seen = new Set<string>();
  let priorCount = 101, priorId = '';
  for (const row of value.cases) {
    if (!row || !exact(row,['id','revision','status','severity','matches']) || typeof row.id !== 'string' ||
        !UUID.test(row.id) || seen.has(row.id) || !Number.isSafeInteger(row.revision) || row.revision < 1 || row.revision > 2147483647 ||
        !['new','triaging','active','closed'].includes(row.status) || !['informational','low','medium','high','critical'].includes(row.severity) ||
        !Array.isArray(row.matches) || !row.matches.length || row.matches.length > visible.size ||
        row.matches.length > priorCount || (row.matches.length === priorCount && row.id <= priorId)) return fail();
    const refs = new Set<string>();
    for (const ref of row.matches) {
      if (!ref || !exact(ref,['index','document_id']) || typeof ref.index !== 'string' || typeof ref.document_id !== 'string' ||
          !visible.has(findingKey(ref)) || refs.has(findingKey(ref))) return fail();
      refs.add(findingKey(ref));
    }
    seen.add(row.id); priorCount = row.matches.length; priorId = row.id;
  }
  return value;
}

export interface TimelineBucket { from: string; until: string; count: number }
export function entityTimeline(report: HuntReport, value?: string): TimelineBucket[] {
  const input = validateHunt(report); // only input fields are projected by validateHunt
  validateHuntReport(report,input);
  if (value !== undefined && !input.values.includes(value)) return fail();
  const from = Date.parse(input.from), until = Date.parse(input.until), duration = until-from;
  // At most 24 contiguous buckets. Explicit half-open range, counts are distinct findings.
  const width = Math.ceil(duration/24);
  const buckets: TimelineBucket[] = [];
  for (let at=from; at<until; at+=width) buckets.push({from:new Date(at).toISOString(),until:new Date(Math.min(at+width,until)).toISOString(),count:0});
  for (const row of report.rows) if (value === undefined || row.matched_values.includes(value)) {
    buckets[Math.floor((Date.parse(row.timestamp)-from)/width)].count++;
  }
  return buckets;
}

export interface GraphNode { id: string; kind: 'value'|'finding'|'incident'; label: string }
export interface GraphEdge { from: string; to: string; kind: 'exact_match'|'linked_finding' }
export function investigationGraph(report: EntityInvestigation, value?: string): {nodes: GraphNode[]; edges: GraphEdge[]} {
  const input=validateHunt(report.hunt);
  validateEntityInvestigation(report,input);
  if (value !== undefined && !input.values.includes(value)) return fail();
  const nodes: GraphNode[]=[], edges: GraphEdge[]=[];
  const values=value===undefined?input.values:[value];
  const valueId=(v:string)=>'value:'+JSON.stringify(v);
  const refId=(r:EntityReference)=>'finding:'+findingKey(r);
  for(const v of values) nodes.push({id:valueId(v),kind:'value',label:v});
  const included=new Set<string>();
  for(const row of report.hunt.rows) {
    const matches=row.matched_values.filter(v=>values.includes(v));
    if(!matches.length) continue;
    const id=refId(row); included.add(id); nodes.push({id,kind:'finding',label:row.document_id});
    for(const v of matches) edges.push({from:valueId(v),to:id,kind:'exact_match'});
  }
  for(const row of report.cases) {
    const matches=row.matches.map(refId).filter(id=>included.has(id));
    if(!matches.length) continue;
    const id='incident:'+row.id;
    nodes.push({id,kind:'incident',label:row.id});
    for(const ref of matches) edges.push({from:ref,to:id,kind:'linked_finding'});
  }
  return {nodes,edges};
}

/** Portable definition only, no results, credentials or automatic browser persistence. */
export function exportHuntDefinition(input: HuntInput): string {
  return JSON.stringify({format:'wazuh-exact-hunt-v1',query:validateHunt(input)},null,2);
}
export function importHuntDefinition(raw: string): HuntInput {
  if (typeof raw !== 'string' || raw.length > 16384) return fail();
  const body=JSON.parse(raw);
  if (!body || !exact(body,['format','query']) || body.format!=='wazuh-exact-hunt-v1' || !body.query ||
      !exact(body.query,['field','values','from','until'])) return fail();
  return validateHunt(body.query);
}
