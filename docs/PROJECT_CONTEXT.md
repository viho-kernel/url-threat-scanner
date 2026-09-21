# URL Threat-Scanner SaaS — Project Context

## How we work

The repository is the single source of truth across AI tools, sessions and machines. Read this file and `docs/PROGRESS.md` before doing project work.

- Work in small, verifiable checkpoints and explain why each component exists.
- Treat generated code as incomplete until Vihari runs it and verifies the result.
- At the end of every phase, update this file and `docs/PROGRESS.md` with exact verified state.
- End each working session with 1–3 sharp questions in the progress log.
- Prefer free and local tooling.
- Before billable infrastructure—including EKS, Palo Alto VM-Series, Transit Gateway, NAT gateways, multi-account environments or duplicate blue-green stacks—verify current free-tier limits, trials, BYOL/licensing and pricing. Build locally, create cloud resources briefly, capture evidence and tear them down.
- The teaching goal is production reasoning and independent troubleshooting, not memorizing commands.

## Operator and career goal

Vihari has about four years of production network/NOC experience with Cisco ASA/FTD/Firepower, Palo Alto NGFW, SD-WAN, BGP, OSPF, VPN, ACI/DNAC, monitoring, incident coordination and RCA. He holds AWS Solutions Architect Associate and Cloud Practitioner certifications and has hands-on exposure to Terraform, Ansible, Docker, Kubernetes, Python and CI/CD.

The goal is a flagship portfolio project for DevOps, AWS cloud security and network security roles. Teach new concepts using trust boundaries, routing, failure domains, observable evidence, rollback and operational ownership. Application development is supporting knowledge; the primary learning outcome is operating and securing the platform.

## Product

The product is a URL Threat-Scanner SaaS.

A user registers or authenticates, submits a URL, and receives an asynchronous threat-analysis result with history and an API. The platform performs:

- strict URL validation;
- suspicious-pattern/static URL analysis;
- DNS resolution;
- controlled HTTP inspection;
- response-header and redirect evidence;
- reputation-provider integration later;
- a risk score, flags and verdict;
- scan ownership and history.

Submitted URLs and fetched content are hostile input. A heuristic result must never be presented as proof that a URL is safe.

## Cloud boundary and job-relevant security scope

AWS is the only implementation cloud. GCP concepts from target job descriptions are translated into AWS equivalents:

- GCP IAM/service accounts → AWS IAM roles, EKS Pod Identity or IRSA;
- GCP networking → VPC, route tables, security groups, NACLs and Kubernetes NetworkPolicies;
- GCP secrets → AWS Secrets Manager and External Secrets Operator;
- GCP Security Command Center → Security Hub, GuardDuty, Config and related evidence.

No GCP environment will be created. Conceptual mappings may be documented for interviews.

The project must cover:

- OWASP web and API risks;
- explicit authentication and authorization;
- tenant isolation and broken-object-level authorization tests;
- SSRF, DNS rebinding, unsafe redirects and private-address protection;
- resource limits and controlled egress;
- secure SDLC and practical vulnerability remediation;
- GitHub Actions hardening, SAST, SCA, secret scanning, SBOM and release evidence;
- structured security events, alerting, investigation, RCA and drills;
- audit-ready architecture and control evidence;
- future AI security: prompt injection, data leakage, connector/tool misuse, cross-tenant retrieval and human approval for unsafe actions.

SOC 2 and ISO 27001 are learning/evidence mappings only, not compliance claims.

## Locked application design

Four independently containerized runtime services:

1. **Gateway — Go**
   - Only public-facing service.
   - Publishes local port `127.0.0.1:8080`.
   - Serves the React UI and public API.
   - Validates hostile URL input.
   - Proxies registration/login/API-key operations to Auth.
   - Calls Scanner with an internal service token.
   - Persists scan ownership and static analysis.
   - Enqueues scan IDs in Redis.
   - Enforces authentication and per-user result authorization.

2. **Auth — Python/FastAPI**
   - Internal-only service on port 8001.
   - Stores users with Argon2 password hashes.
   - Issues and validates short-lived JWTs.
   - Creates, hashes, verifies and revokes API keys.
   - Validates the active user behind every credential.
   - Requires a Gateway-to-Auth service token.

3. **Scanner — Python/FastAPI**
   - Internal-only service on port 8000.
   - Performs static URL/pattern analysis.
   - Returns verdict, risk score and flags.
   - Requires a Gateway-to-Scanner service token.
   - Does not perform uncontrolled outbound fetching.

4. **Worker — Node.js**
   - Internal background service with no published port.
   - Atomically moves Redis jobs from `scan-jobs` to `scan-jobs:processing`.
   - Recovers interrupted processing jobs after restart.
   - Resolves DNS and rejects private/special destinations.
   - Pins the approved address used for the HTTP connection.
   - Revalidates redirects and limits redirects, body size and timeout.
   - Distinguishes temporary retryable failures from permanent/security failures.
   - Writes completed/failed evidence to PostgreSQL and acknowledges Redis jobs only after persistence.

Local state services:

- PostgreSQL stores users, API keys, scan ownership, lifecycle, static analysis and worker results.
- Redis is the asynchronous work queue, not the system of record.

If the polyglot workload becomes unhelpful, the Worker may later move to Python while retaining Go and Python. This is not currently planned.

## Phase 1 verified implementation

Phase 1 was completed on 2026-09-21.

The local Compose platform runs six containers: Gateway, Auth, Scanner, Worker, PostgreSQL and Redis. Only Gateway is exposed to the host application path. PostgreSQL is host-bound only for local administration; Auth and Scanner use internal Compose networking.

Verified capabilities:

- React interface embedded into the Go binary and served from `/`;
- registration, automatic login, login and session exit;
- bare-domain UI normalization to HTTPS while Gateway validation remains authoritative;
- JWT authentication;
- API-key creation, verification, expiry metadata, last-used timestamp and revocation;
- internal service tokens between Gateway and Auth/Scanner;
- individual-user tenant model;
- ownership filter on scan retrieval using both scan ID and user ID;
- static analysis persisted as PostgreSQL JSONB;
- asynchronous status lifecycle: queued → running → completed/failed;
- worker attempts, timestamps, result JSON and safe error codes;
- DNS/HTTP inspection with bounded redirects, timeout and body sample;
- SSRF protection for localhost, private, link-local, multicast and special addresses;
- DNS pinning to reduce DNS-rebinding risk;
- queue recovery and retry classification;
- health and readiness endpoints;
- structured application events;
- non-root application containers;
- lockfiles and multi-stage builds;
- generated `node_modules` and frontend `dist` excluded from Git;
- real end-to-end scans verified through UI and API;
- source pushed to `viho-kernel/url-threat-scanner`.

Verified Phase 1 traffic flow:

Browser or API client → Go Gateway → Auth verification and Scanner static analysis → PostgreSQL scan record → Redis pending queue → Node Worker → controlled public DNS/HTTP target → PostgreSQL result → authenticated Gateway result query.

## Authentication and trust decisions

Three credentials serve different purposes:

- **JWT:** short-lived end-user browser/API session credential.
- **API key:** long-lived automation credential; only a SHA-256 hash and display prefix are stored.
- **Service token:** shared internal Phase 1 credential proving that a request came through the Gateway.

Service tokens are a local baseline, not the final production identity mechanism. In Kubernetes/AWS they will be replaced or strengthened using NetworkPolicies, workload identity, Secrets Manager/External Secrets and transport security as appropriate.

The React application keeps its JWT only in page memory. Refreshing or exiting removes it. Future browser-security work includes a formal CSP, secure headers and deciding whether production should use hardened HttpOnly cookies instead.

## URL and network-security decisions

The React UI may prepend `https://` to a bare domain for usability. This is not a security control. The Gateway independently requires HTTP/HTTPS, a hostname, approved ports, no embedded credentials, no fragments, and rejects literal private/special IPs.

The Worker performs the decisive outbound security checks at request time:

- resolves every address;
- rejects the destination if any resolved address is not public;
- pins the selected approved address during connection;
- applies the same controls to redirects;
- limits redirects, timeout and body sample;
- records resolved and connected addresses;
- never treats fetched content as trusted code.

Temporary DNS failures such as `EAI_AGAIN` are retryable. Invalid domains and security-policy violations fail without repeated outbound attempts.

## Phase 1 limitations and deferred improvements

These are documented gaps, not hidden claims:

- Static heuristics and network inspection do not prove a site is safe.
- Reputation integration is represented as `not_configured`.
- ASN/GeoIP hosting intelligence is deferred; CDN addresses may not identify the origin.
- Redis list processing is a local baseline; later evaluate Redis Streams, a managed queue or `BLMOVE`.
- Service tokens are shared secrets without rotation or mTLS.
- PostgreSQL and Redis use local development credentials.
- Existing early scan rows may have nullable ownership fields.
- The UI design and colour system will be refined later.
- The UI has no full scan-history list endpoint yet.
- Automated Go and Worker security tests exist; Auth/Scanner and cross-service test coverage must expand in the CI/CD phase.
- Formal rate limiting, quotas, CSP, secure response headers and production session-cookie design remain future security work.
- GeoIP/reputation caching must be designed with controlled egress, privacy, licensing and provider-failure handling.
- Local Compose is not a production orchestrator.

## Target platform and domains

- Local Kubernetes using kind or k3s; EKS only during cloud phases.
- Multi-AZ VPC with public, private application and data tiers.
- A second VPC or on-premises simulator connected with site-to-site IPsec, BGP and Transit Gateway.
- Security groups, NACLs, Kubernetes NetworkPolicies and controlled scanner egress.
- Palo Alto VM-Series inspection configured through Ansible policy-as-code.
- EKS behind ALB plus S3, Route 53 and IAM.
- GuardDuty, Security Hub, Config, CloudTrail, IAM Access Analyzer, KMS, Secrets Manager and Falco.
- GitHub Actions only: tests, CodeQL/Semgrep, Gitleaks, Trivy/Snyk, tfsec/checkov and OPA/Conftest.
- Argo CD pull-based reconciliation.
- External Secrets Operator with AWS Secrets Manager; no Kubernetes secrets in Git.
- Ansible for host hardening, VPN/BGP simulation and Palo Alto policies.
- Bash for repeatable build, deployment, smoke-test and triage workflows.
- Parameterized Terraform for all AWS infrastructure.
- Separate AWS Organizations accounts for dev, staging and production.
- Promotion from dev to staging to production with approvals and blue-green production deployment.
- Prometheus, Grafana, Loki and Alertmanager.
- Resilience testing, backup/restore and documented incident/patching runbooks.
- Future AIOps after the platform produces trustworthy structured telemetry.

## Phase checkpoints

0. Repository skeleton and living context/progress documents. **Completed.**
1. Four polyglot services integrated locally through Compose with service authentication. **Completed.**
2. Local Kubernetes deployment with NetworkPolicies and container hardening.
3. Terraform AWS network foundation: multi-account VPCs, subnets and Transit Gateway.
4. Ansible-managed VPN and BGP hybrid simulator.
5. Palo Alto VM-Series, AWS security monitoring and Falco.
6. Terraform-managed EKS.
7. GitHub Actions pipeline and security gates.
8. Argo CD and External Secrets.
9. Multi-environment promotion and blue-green deployment.
10. Observability stack.
11. Resilience/DR and failure test.
12. Incident and patching runbooks.
13. Future AIOps and AI product-security layer.

## Cost discipline

Phase 0 and Phase 1 are local and incur no AWS infrastructure cost. Before every cloud phase, confirm account/billing status, service quotas, current free-tier eligibility, NAT/TGW/EKS/VM-Series costs and Palo Alto licensing. Use budgets and alerts, minimize runtime, capture evidence and destroy resources after proof.
