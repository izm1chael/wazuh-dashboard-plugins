# Historical entity and IOC hunt

Status: experimental development candidate, not production qualified. No deployment or external enrichment. Matching indexer and dashboard builds required.

## Workflow

From the incident workspace select Threat hunting, or load an incident investigation timeline, select a visible entity and prepare a hunt for one of its observed source fields. Searches never start automatically. Choose one exact field, up to 20 unique literal values (OR), inclusive UTC start and exclusive UTC end. Browser defaults to the preceding 24 hours. Maximum range seven days, maximum 100 results, request timeout 15 seconds. Return distinct findings, their timestamps and exact matching input values, plus per-value counts in the UI. No raw sources, query DSL, external indicator reputation, automated classification or scheduled matching. In incident context a human can explicitly attach a finding via the existing owner/revision/visibility-checked mutation; no batch attach or automatic mutation.

## Supported source fields and limits

Wazuh agent ID/name; host ID/name/hostname/IP; source and destination IP; user name/ID/domain; DNS question name; MD5, SHA-1 and SHA-256. Exact spelling/case; IP values are canonical IPv4 literals only in this version. Hash lengths are validated but casing is not rewritten. A timeline entity projection may have normalized a hash or trimmed text, so a prepared search may need analyst correction. No wildcard syntax, CIDR, IPv6, free-form raw event search or field normalization. Actual field mapping and retained findings determine coverage. Empty results do not prove absence or benignity.

## Permission and execution boundaries

Dedicated cluster action `cluster:admin/wazuh/incident/hunt_read`, experimental incidents feature gate and authenticated principal. The search executes using the original caller context against the fixed `wazuh-findings-v5*` pattern and requires the caller's existing finding-search permissions. No elevated search, caller-selected index, arbitrary DSL or backing-case-index grant. Source filtering requests only timestamp and chosen field; exact literal values must be confirmed in returned caller-visible source. Unconfirmed, malformed, ambiguous dotted/nested source or over-budget extraction rejects the entire response. Partial shards, timeout, early termination, non-exact totals, duplicate references or more than 100 findings fail closed. The dashboard uses a single in-flight search per process; the indexer service has two permits per instance. These are local concurrency controls, not cluster-wide quotas or guarantees of bounded shard-level work. No hunt result persistence; clearing, editing or leaving the page removes the local display. A completed result is not an atomic permission snapshot and may become stale; attaching rechecks source visibility.

## Agentic SOC

Existing Agentic SOC probes remain unchanged. A future entity-history probe should be separately opt-in, select a sample reference rather than model-supplied entity values, use the fixed current-user hunt endpoint, enforce current incident revision and disclosure policy, and share only aggregate coverage/count facts. No raw entity values, returned finding IDs, unrestricted query access or automatic attach should be provided to the model. Not implemented in this batch.

## Qualification

1. Build both plugins and run full Gradle/Jest and static role fixture suites. Test the default-disabled gate and isolated hunt grant.
2. On disposable RC2, test hunt grant alone, finding-search permission alone, both grants, different document-level and field-level security, and revoked permissions. Verify no raw source, unrelated matches or direct case backing-index access. Test all 15 real field mappings (including nested/dotted and multivalued sources), no results, exact 100 results, more than 100, failed shards, timeouts, aliases/backing references, and incomplete source projection. No claim of support for unmapped fields until exercised.
3. Check direct transport and dashboard request limits, malformed/duplicate JSON, UTC boundaries, concurrency and response validation. Exercise release after failures; test the local UI controls, field/value edits, timeline pivot and navigation, explicit attachment under ownership and stale revision checks. Verify no provider calls or new external disclosures.
4. Record exact SHAs, build and browser results, representative fixtures and actual role matrix. Any mapping or authorization failure blocks production qualification.

Cloud evidence: 18 source-level cross-repository checks passed, including field allowlist parity, dedicated grant, routes, feature gate, current-user path, query limits, minimal projection and UI attachment wiring. Exact TypeScript contract blob `27da0e5ebd1d0e386682fd27415fad1a43a9cc1c` was compiled under `tsc --strict --target es2020 --module commonjs`; 38 standalone Node assertions passed. Java and Jest regression sources added; full builds and actual OpenSearch/DLS/FLS tests not executed.
