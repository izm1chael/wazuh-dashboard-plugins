# WUCF Dashboard candidate (not mounted)

Tracks epic #18 and children #19/#20. Base 22901fa354f20616d4bc707003b4b8a115cfb3d9.
Core draft: izm1chael/wazuh#8. Coordinate schema with tools/wucf/catalogue.py
and health.py. Local catalogue entries are placeholders until an authorized
server returns reviewed versions. Candidate permissions are not exhaustive.

The EUI component provides search, setup preview, prerequisites and bounded
poll interval. It does not collect secrets, call a server, save or activate.
The health parser is fail-closed, but it is not an authorization boundary:
the server must derive environment scope from authenticated identity.

RC2 app-router.tsx (blob 00466580ecdb4a1b96e11beabad954996cf96f9d) uses
existing WzRequest manager session setup and routes. Do not register the
candidate until manager-side RBAC, CCS/session scope, read-only catalogue,
write-only credential endpoint, protected configuration persistence and
native ingestion qualification are proven. No changes to app-router,
existing SOC or WADE code. Build, Jest, EUI, accessibility and browser
acceptance remain open.
