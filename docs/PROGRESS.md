# URL Threat Scanner — Progress

## Phase status

- Phase 0: **Completed**
- Phase 1: **Completed on 2026-09-21**
- Current phase: **Phase 2 — not started**
- Next checkpoint: container hardening review, local Kubernetes manifests and NetworkPolicies
- AWS cost incurred so far: **none**

## Phase 0 — completed

- Initialized the repository.
- Created `README.md`.
- Created the living context and progress documents.
- Verified Git and Docker Desktop.
- Established the local-first and cost-control workflow.

Key commits included:

- `a6e0d4c` — Initialize URL threat scanner repository
- `daadeb2` — Document project scope and Phase 0 progress

## Phase 1 — completed

### Local architecture

Six Compose containers are operational:

1. Go Gateway with embedded React UI
2. Python/FastAPI Auth
3. Python/FastAPI Scanner
4. Node.js Worker
5. PostgreSQL
6. Redis

Only the Gateway is the product entry point and is published on `127.0.0.1:8080`. Auth and Scanner are internal services. Worker is a background consumer.

### Gateway

- `GET /health`
- `GET /ready`
- `POST /auth/register`
- `POST /auth/login`
- `POST /api-keys`
- `POST /api-keys/revoke`
- `POST /scans`
- `GET /scans/{id}`
- Strict request-size and JSON parsing.
- Strict HTTP/HTTPS URL validation.
- Rejects embedded credentials, fragments, unexpected ports, localhost and literal private/special addresses.
- Requires JWT or API key for scan operations.
- Applies user ownership to result retrieval.
- Calls Auth and Scanner using internal service tokens.
- Persists static analysis and queues scan IDs.
- Serves the embedded React production build.
- React normalizes bare domains to HTTPS for usability; Gateway remains authoritative.
- Runs as non-root UID/GID `65532:65532` in a scratch runtime image.

### Auth

- User registration and login.
- Argon2id password hashing.
- Short-lived HS256 JWT with subject, issuer, audience, issue time, expiry and JTI.
- Active-user verification.
- API-key creation using a `uts_` prefix.
- Only API-key hash and prefix stored.
- Expiration metadata, last-used timestamp and revocation.
- Internal service-token requirement.
- Individual-user tenancy for Phase 1.

### Scanner

- Internal-only FastAPI service.
- Static URL analysis.
- Verdict, risk score and suspicious flags.
- Internal service-token requirement.
- Structured analysis event logs.

### Worker

- Redis pending and processing queues.
- Atomic job movement using `BRPOPLPUSH`.
- Interrupted-job recovery.
- PostgreSQL lifecycle updates.
- DNS resolution and public-address enforcement.
- Blocks private, loopback, link-local, multicast and special IPv4/IPv6 ranges.
- DNS-pinned HTTP connection to reduce rebinding risk.
- Redirect revalidation.
- Timeout, redirect and response-body limits.
- Selected response-header capture.
- Safe error codes and bounded retry attempts.
- Temporary DNS failures retry; security/permanent failures do not.
- Completion is persisted before queue acknowledgement.
- Five network-security tests pass.

### PostgreSQL

Stores:

- users and Argon2 password hashes;
- API keys as hashes and prefixes;
- scan owner;
- URL and lifecycle status;
- static analysis as JSONB;
- worker result as JSONB;
- safe error message;
- attempts and timestamps.

### Redis

- `scan-jobs` pending queue.
- `scan-jobs:processing` in-flight queue.
- Both queues verified empty after successful processing.
- Redis is transport, while PostgreSQL is the authoritative record.

### React UI

- Embedded into the Go binary through a Node build stage and Go `embed`.
- Registration followed by automatic login.
- Sign in and exit-session behavior.
- JWT retained only in page memory.
- Bare-domain normalization.
- Animated scan lifecycle.
- Static and network risk results.
- DNS/HTTP evidence and flags.
- Responsive layout.
- Visual design is functional but intentionally remains open for future refinement.

## Security evidence verified

- Direct metadata endpoint `169.254.169.254` rejected before queueing.
- Private and special IPv4/IPv6 unit tests pass.
- DNS pinning records the exact connected address.
- Redirect destinations are independently validated.
- Tenant isolation tested: another user receives 404 for a scan they do not own.
- Invalid/revoked credentials return unauthorized responses.
- API-key SHA-256 output matched the stored hash.
- API-key `last_used_at` was updated after verification.
- Revoked API key stopped authenticating.
- Service tokens protect Auth and Scanner.
- Real secrets remain in ignored `.env`; `.env.example` contains placeholders only.
- Generated `node_modules` and frontend `dist` are ignored and removed from the tracked tree.
- Application services run as non-root.
- Gateway health verified: `{"service":"gateway","status":"ok"}`.
- Gateway readiness verified with PostgreSQL and Redis connected.
- Redis pending and processing queue lengths verified as zero.
- Full scans verified through API and React UI.

## End-to-end request flow

1. User registers or signs in through the React UI.
2. Browser sends requests only to the Go Gateway.
3. Gateway proxies identity requests to internal Auth using a service token.
4. Auth returns a JWT after validating the Argon2 password hash.
5. User submits a URL with the JWT or an API key.
6. Gateway authenticates the credential through Auth.
7. Gateway validates the URL and calls Scanner for static analysis.
8. Gateway stores an owned PostgreSQL record with status `queued`.
9. Gateway pushes only the scan ID into Redis.
10. Worker atomically claims the scan and marks it `running`.
11. Worker loads the URL from PostgreSQL.
12. Worker resolves and validates every destination address.
13. Worker performs a bounded, DNS-pinned HTTP request.
14. Worker stores result/error evidence and marks the scan completed or failed.
15. Worker removes the job from the processing queue.
16. UI polls the authenticated Gateway result endpoint and renders the final evidence.

## Important failures diagnosed during Phase 1

- Docker Desktop engine initially hung and required recovery/reinstallation.
- Alpine-based images intermittently produced `exec format error`; build/runtime bases were changed to Bookworm/slim variants.
- Git Bash path conversion broke Docker volume/workdir arguments; `MSYS_NO_PATHCONV=1` was used.
- Missing Go module checksums and imports blocked builds.
- Duplicate Go types/routes caused compile and startup failures.
- Database code was repaired after malformed incremental edits.
- Auth failed when JWT import and API-key response models were missing.
- Duplicate/malformed Auth verify routes caused 422 responses.
- Gateway registration proxy contained a `/reigster` typo.
- Docker storage filled the C drive; Docker data was moved and cache cleaned while preserving named volumes.
- Browser `type=url` prevented bare-domain normalization; UI input was changed to text while Gateway validation stayed strict.
- Git Bash history expansion corrupted JSON containing `!`; safe quoting/printf was used.
- Accidentally tracked Worker `node_modules` was removed and ignored.
- An accidental empty `verdict` file was identified for deletion.

## Phase 1 limitations/backlog

- Reputation provider is not configured.
- ASN/GeoIP hosting intelligence is deferred.
- UI colours and visual identity need later refinement.
- No complete scan-history list endpoint yet.
- JWT browser storage strategy is a Phase 1 memory-only baseline.
- CSP, security response headers, formal CORS/CSRF policy and rate limiting remain to be implemented.
- Auth and Scanner need broader automated test suites.
- Service-token rotation, workload identity and transport security come in later phases.
- Redis list queue should be reassessed before production.
- Local PostgreSQL and Redis credentials are development-only.
- Legacy scan rows may have nullable ownership.
- Caching strategy will be added when reputation/GeoIP providers are introduced.
- No claim is made that heuristic analysis proves a destination safe.

## Repository checkpoint

Remote:

`https://github.com/viho-kernel/url-threat-scanner`

Verified commits include:

- `f8b3584` — Complete asynchronous URL scan lifecycle
- `b2d0902` — Persist static URL analysis with scan history
- `5e358d4` — Build local polyglot URL threat scanner platform

The Phase 1 documentation update follows these commits.

## Phase 2 entry plan

Phase 2 will move the same application from Compose to a local Kubernetes cluster.

Before implementation:

1. Review available RAM because the host has approximately 5.8 GB total and Docker is constrained.
2. Choose kind or k3s based on resource usage and Windows/Docker compatibility.
3. Map every Compose service, environment variable, volume, health check and dependency to a Kubernetes object.
4. Define namespace and trust zones.
5. Create ConfigMaps for non-secrets and temporary local Secrets only as a lab bridge; never commit real secret values.
6. Add startup, readiness and liveness probes.
7. Add CPU/memory requests and limits.
8. Add default-deny ingress/egress NetworkPolicies.
9. Permit only required service paths.
10. Prove that unauthorized pod-to-pod and Worker egress paths are blocked.

Do not start Phase 2 until the Phase 1 architecture walkthrough is understood.

## Next session questions

1. Can Vihari explain the complete request path from browser authentication through Redis processing to PostgreSQL result retrieval?
2. For the low-memory Windows host, should Phase 2 use kind or k3s, and what resource ceiling should be reserved?
3. Which exact pod-to-pod and outbound flows must the Phase 2 default-deny NetworkPolicies permit?
