import type { FindingObservation } from '../../../../common/incidents/contracts';

export function summarizeFindings(observations: FindingObservation[]) {
  const entities = new Map<string, { kind: string; value: string; count: number; fields: string[] }>();
  const techniques = new Set<string>();
  const tactics = new Set<string>();
  for (const finding of observations) {
    const seen = new Set<string>();
    for (const entity of finding.entities) {
      const key = JSON.stringify([entity.kind, entity.value]);
      const current = entities.get(key) ?? { kind: entity.kind, value: entity.value, count: 0, fields: [] };
      if (!seen.has(key)) current.count++;
      seen.add(key);
      if (!current.fields.includes(entity.field)) current.fields.push(entity.field);
      entities.set(key, current);
    }
    finding.techniques.forEach(id => techniques.add(id));
    finding.tactics.forEach(id => tactics.add(id));
  }
  const time = (item: FindingObservation) => item.timestamp === null ? Number.POSITIVE_INFINITY : Date.parse(item.timestamp);
  const ordered = [...observations].sort((a, b) => {
    const first = time(a), second = time(b);
    const left = Number.isNaN(first) ? Number.POSITIVE_INFINITY : first;
    const right = Number.isNaN(second) ? Number.POSITIVE_INFINITY : second;
    return (left === right ? 0 : left < right ? -1 : 1) ||
      a.index.localeCompare(b.index) || a.document_id.localeCompare(b.document_id);
  });
  return { entities: [...entities.values()].sort((a, b) => b.count - a.count || a.kind.localeCompare(b.kind) || a.value.localeCompare(b.value)),
    techniques: [...techniques].sort(), tactics: [...tactics].sort(), ordered };
}
