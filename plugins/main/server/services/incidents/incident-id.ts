import { IncidentDomainError } from './incident-domain';

export function validateIncidentId(id: string): void {
  if (typeof id !== 'string' ||
      !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id)) {
    throw new IncidentDomainError('invalid', 'Invalid incident ID');
  }
}
