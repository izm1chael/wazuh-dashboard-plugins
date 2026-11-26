import {
  applyIncidentCommand,
  createIncident,
  CreateIncident,
  Incident,
  IncidentCommand,
  IncidentDomainError,
} from './incident-domain';
import { VersionedIncident } from './incident-store';

export type IncidentPermission = 'read' | 'create' | 'assign' | 'transition' | 'close' | 'reopen';
export interface IncidentPrincipal {
  readonly username: string;
}

/** The implementation must resolve grants from a trusted server-side security
 * boundary, not client-supplied roles. No permissive default is provided. */
export interface IncidentAuthorizer {
  require(principal: IncidentPrincipal, permission: IncidentPermission): Promise<void>;
  requireAssignableOwner(principal: IncidentPrincipal, owner: string): Promise<void>;
}

export interface IncidentPersistence {
  get(id: string): Promise<VersionedIncident>;
  create(record: Incident): Promise<VersionedIncident>;
  commit(previous: VersionedIncident, record: Incident): Promise<VersionedIncident>;
  deliverPending(previous: VersionedIncident): Promise<VersionedIncident>;
}

export interface IncidentMutationResult {
  incident: Omit<Incident, 'pending_activity'>;
  activityDelivery: 'delivered' | 'pending';
}

const permissions: Record<IncidentCommand['kind'], IncidentPermission> = {
  assign: 'assign', start_triage: 'transition', activate: 'transition',
  close: 'close', reopen: 'reopen',
};

export function validateIncidentId(id: string): void {
  if (typeof id !== 'string' ||
      !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id)) {
    throw new IncidentDomainError('invalid', 'Invalid incident ID');
  }
}

function requirePrincipal(principal: IncidentPrincipal): void {
  if (!principal || typeof principal.username !== 'string' || !principal.username.trim() ||
      principal.username.length > 1024 || principal.username !== principal.username.trim()) {
    throw new Error('Authenticated incident principal required');
  }
}

export function publicIncident(record: Incident): Omit<Incident, 'pending_activity'> {
  const { pending_activity, ...incident } = record;
  return incident;
}

/** Internal single-SOC service. Not an HTTP route and not a substitute for
 * dedicated indexer action permissions or protection against direct writes. */
export class IncidentService {
  constructor(
    private readonly store: IncidentPersistence,
    private readonly authorization: IncidentAuthorizer,
    private readonly generateId: () => string,
    private readonly clock: () => string,
    private readonly reportPendingDelivery: (incidentId: string, error: unknown) => void,
  ) {}

  async get(principal: IncidentPrincipal, id: string): Promise<Omit<Incident, 'pending_activity'>> {
    requirePrincipal(principal);
    await this.authorization.require(principal, 'read');
    validateIncidentId(id);
    return publicIncident((await this.store.get(id)).record);
  }

  async create(principal: IncidentPrincipal, input: CreateIncident): Promise<IncidentMutationResult> {
    requirePrincipal(principal);
    await this.authorization.require(principal, 'create');
    const record = createIncident(input, this.generateId(), principal.username, this.clock());
    return this.finish(await this.store.create(record));
  }

  async command(
    principal: IncidentPrincipal, id: string, expectedRevision: number, command: IncidentCommand,
  ): Promise<IncidentMutationResult> {
    requirePrincipal(principal);
    if (!command || !Object.prototype.hasOwnProperty.call(permissions, command.kind)) {
      throw new IncidentDomainError('invalid', 'Unknown incident command');
    }
    await this.authorization.require(principal, permissions[command.kind]);
    validateIncidentId(id);
    if (!Number.isSafeInteger(expectedRevision) || expectedRevision < 1) {
      throw new IncidentDomainError('invalid', 'Expected a positive incident revision');
    }
    if (command.kind === 'assign' && command.owner !== null) {
      if (typeof command.owner !== 'string' || !command.owner.trim() ||
          command.owner !== command.owner.trim() || command.owner.length > 1024) {
        throw new IncidentDomainError('invalid', 'Invalid assignee');
      }
      await this.authorization.requireAssignableOwner(principal, command.owner);
    }
    const previous = await this.store.get(id);
    if (previous.record.revision !== expectedRevision) {
      throw new IncidentDomainError('conflict', 'Incident changed; reload before retrying');
    }
    const next = applyIncidentCommand(previous.record, command, principal.username, this.clock());
    return this.finish(await this.store.commit(previous, next));
  }

  /** The aggregate has already committed. Delivery failure is not a rollback.
   * Recovery must retry the persisted event; never repeat the logical command. */
  private async finish(committed: VersionedIncident): Promise<IncidentMutationResult> {
    try {
      const delivered = await this.store.deliverPending(committed);
      return { incident: publicIncident(delivered.record), activityDelivery: 'delivered' };
    } catch (error) {
      try { this.reportPendingDelivery(committed.record.id, error); } catch (_) {
        // A reporting outage must not turn an acknowledged write into failure.
      }
      return { incident: publicIncident(committed.record), activityDelivery: 'pending' };
    }
  }
}
