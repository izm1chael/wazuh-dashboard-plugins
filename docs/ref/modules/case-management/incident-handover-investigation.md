# Analyst handover and bounded investigation view

Status: implemented in the experimental fork, not runtime qualified. No upstream submission, production deployment or rule changes.

## Handover

- Open incidents with an owner support offer, accept and cancel/decline. The current owner remains accountable until acceptance. Only the owner can offer; only the exact authenticated target can accept; either participant can cancel. All three fixed commands require the existing assignment action grant, a positive expected revision and delivered prior audit. There is no forced supervisor assignment, directory validation, escalation, notification or expiry.
- No assignment/lifecycle timestamp is reset on acceptance. Closure and return-to-queue are blocked while an offer exists. Reasons are required and stored in internal activity; they are not exposed by the ordinary summary/activity projection. Use an investigation note to share context.
- My open incidents and Incoming handovers are open-status queues. The transport supplies the authenticated principal to the fixed query, never a caller-supplied target. This is a filter within the existing single-SOC incident-read authorization model, not per-incident ACL isolation. Other authorized incident readers can see the pending recipient. An optional owner filter only further narrows results.
- Mapping addition: strict handover object, exact keyword target, non-indexed offered_by and offered_at. For existing .wazuh-cases-v1 installations, qualify additive mapping upgrade before enabling the workflow; a template change alone does not upgrade an existing index. Existing records without the field project as null. Do not deploy a transitional commit with the earlier disabled-object mapping. No rolling mixed-version qualification has been performed.

## Investigation view

Explicit on-demand read of at most four 25-position linked-finding pages, four 50-event activity pages and a final incident summary. Verify revision, identity, cursor advancement, unique references, visible/unavailable/remaining conservation and audit ordering. Any inconsistent response, failure or revision drift discards partial output. Cancellation suppresses late results and prevents further reads, not an already in-flight HTTP request. The view is a live, bounded caller-visible projection, not an immutable snapshot, evidence archive, or atomic authorization snapshot. Source permission revocation/retention after a read remains possible. Missing timestamps are shown as unknown, and missing revisions, pending audit, capped scope and unavailable findings are reported. The first 100 positions are not selected by time. Entity pivot covers up to 250 frequency-ranked distinct observed entities; ATT&CK rollups cover visible scanned observations only. No global hunting, raw-source search, external disclosure or mutation.

## Disposable qualification

1. Compile both plugins and run existing Gradle/Jest/Python gates. Verify mapping installation fresh and on earlier foundation data, with no direct backing-index access.
2. Create separate users Alice, Bob and Eve. Verify owner-only offer, recipient-only acceptance, either-participant cancellation, missing assignment grant denied, forged actor rejected, stale revision and concurrent accept/cancel conflict; check all timestamps, owner and activity receipt. Verify old-owner actions fail after acceptance, closure/unassign blocked while pending, cancellation retains owner. Validate exact case-sensitive principal matching and self/shared target rejection.
3. Verify personal queues with all three authenticated users, optional owner filter, pagination and closed exclusion. No body/query actor override. Verify recipient displayed only to existing incident readers.
4. Verify timeline with zero findings, hidden/expired findings, 26 and 125 positions, >200 activity events, unknown timestamps, duplicate/missing audit revisions, malformed projection, revision drift and page permission changes. Confirm clear/reload/unmount removes results and late requests cannot repopulate; verify no direct index request or new permission.
5. Check pending audit mutation disables all workspace writes until reload; server remains authoritative. Verify audit recovery and no hidden retry.

Cloud checks: 15 source-level cross-repository contract assertions passed. Exact investigation-snapshot.ts blob 6b4b49e65ca8068d9c996e7bb9c1e9dc78ca2ec4 compiled with tsc --strict against the relevant shared contract shapes and passed nine Node mock assertions. Full plugin builds, Java/Jest suites, actual OpenSearch queries, browser tests and role qualification have not run.
