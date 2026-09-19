# URL Threat-Scanner SaaS — project context

## How we work

The repository is the source of truth across AI tools, sessions, and machines. Read this file and `docs/PROGRESS.md` first. Work in small, precise checkpoints. At the end of every phase, output the exact updated contents of both files for committing. End each session with 1–3 sharp questions in the progress log. Prefer local/free tooling. Before billable infrastructure (EKS, VM-Series, TGW, NAT, multiple accounts, duplicate blue-green environments), check current free tier, trial, BYOL and license terms; build locally, launch for a brief proof, record evidence, tear down. Verify live prices and terms at deployment time.

## Starting point — explicit reset

As of 2026-09-18, the operator has not implemented, installed, built, tested, or committed any part of this project. Earlier AI-generated source files and archives are drafts, not evidence of completed work or the operator's repository. Begin at absolute beginner level: define a term in plain words, explain why this product needs it, do one small action, inspect its output, and only then advance. Do not treat a generated file as finished until the operator creates/runs and verifies it. Phase 0 is currently in progress, not complete.

## Operator and goal

Vihari: ~4 years of production network operations (Cisco ASA/FTD/Firepower, Palo Alto NGFW, SD-WAN, BGP, OSPF, VPN, ACI/DNAC), AWS SAA and Cloud Practitioner, hands-on Terraform, Ansible, Docker, Kubernetes, Python and CI/CD. Transitioning into DevSecOps/Cloud Security. Teach the network concepts as we implement them, explain decisions using routing, trust boundaries and failure domains. Aim for a flagship interview project with the network and security layer as its strength.

## Product

Submit a URL; asynchronously inspect DNS, HTTP headers/response, reputation, and suspicious patterns; return a threat verdict, scan history and API. URLs are hostile input. Scanner and worker require isolation and controlled egress. Tie each architecture decision to this product. A limited heuristic verdict must never claim a URL is safe.

## Cloud boundary and job-relevant security scope (locked 2026-09-18)

AWS is the only implementation cloud. Translate the job description's GCP IAM, service accounts, networking, secrets, workload isolation and Security Command Center themes into AWS IAM/roles and EKS Pod Identity or IRSA, VPC controls, Secrets Manager, EKS workload security, Security Hub/GuardDuty/Config. Do not create a GCP environment. Explain the conceptual GCP mapping in interview notes only.

- Secure development and API security: a short threat model and data-flow diagram for URL input, service calls, queue, database, third-party reputation sources and egress; trust-boundary tests for SSRF, DNS rebinding, redirects, credential exposure, API key/JWT misuse, broken object authorization, tenant isolation and resource exhaustion. Add negative authorization tests and an API inventory. Make authorization explicit on every history/result query. Treat fetched pages and reputation responses as untrusted data.
- Product-facing UI: add a minimal React client later, built as static assets served by the Go gateway, preserving four runtime services. Cover browser session/token handling, output encoding, CSP, CORS and CSRF where applicable. Decide the browser authentication approach before implementing it.
- GitHub and supply chain: protected PR review, least-privilege workflow permissions, pinned actions/dependencies, OIDC to AWS with constrained trust, secret scanning, SAST, dependency and container scanning, IaC/policy gates, SBOM and provenance/attestation, signed or verified release artifacts where practical. Define which findings block release and how exceptions expire.
- Vulnerability management: triage findings using exploitability, reachability, asset exposure and business impact; record owner, severity, due date, evidence, remediation PR and validating re-scan. Demonstrate fixing at least one actual issue rather than merely reporting tool output.
- Assurance and response: structured security events with redaction and correlation IDs, alert and investigation path, a safe incident drill, RCA, threat-model revisions, penetration-test scope/evidence and audit-ready control-to-evidence mapping. SOC 2/ISO 27001 are learning mappings, not a compliance or certification claim.
- Future AIOps security: when Phase 13 adds an alert-triage assistant or RAG, treat logs, scanned page text, connector data and retrieved documents as hostile. Test prompt injection, cross-tenant retrieval, sensitive-data leakage, excessive tool privileges, unsafe automated actions, output handling and cost/usage abuse. Read-only draft recommendations first; human approval for actions. No AI feature is required for the Phase 1 scanner.

## Locked application design

Four independently containerized services: Go gateway/public API (only internet-facing service); Python/FastAPI auth (users, API keys, JWT); Python scanner/core (analysis, reachable only from gateway); Node.js worker (consumes queue, makes controlled outbound requests, writes DB). If three languages overwhelm the operator, worker may move to Python while preserving Go+Python. Explain optimized per-language multi-stage images: Go to distroless, Python to slim, Node to suitable runtime; measure image size and attack surface. Local state uses Redis queue and Postgres database. Gateway calls auth and scanner with an internal token; clients use API key or JWT; only gateway publishes a local port. Worker independently validates DNS at request time and pins approved destination; redirects are not followed. Phase 1 implementation is a lab baseline, with limitations listed in PROGRESS.

## Target platform and domains

- Local Kubernetes kind/k3s for iteration; Terraform-managed EKS only in cloud phases. Teach managed control plane versus node data plane and pod networking.
- Multi-AZ VPC with public/private/data tiers, routing/NAT; second VPC or on-prem simulator via site-to-site IPsec VPN with BGP over Transit Gateway.
- SGs, NACLs, Kubernetes NetworkPolicies, controlled scanner egress; Palo Alto VM-Series inspection configured using Ansible policy-as-code.
- EKS behind ALB; S3, Route 53, IAM. GuardDuty, Security Hub, AWS Config, CloudTrail, IAM Access Analyzer, KMS, Secrets Manager and Falco.
- GitHub Actions only: tests; CodeQL/Semgrep SAST, Gitleaks secrets, Trivy/Snyk SCA, Trivy image scanning, tfsec/checkov IaC scanning, OPA/Conftest gate. Check licenses and practical overlap at implementation time.
- Argo CD pull-based GitOps; External Secrets Operator with AWS Secrets Manager; no secrets in Git or Kubernetes manifests.
- Go/Python/Node for services; Docker multi-stage images; Ansible for host CIS hardening, VPN simulator IPsec+BGP using FRRouting and Palo Alto policies; Bash for build/deploy/smoke/triage; parameterized Terraform for AWS.
- Separate AWS Organizations dev/staging/prod accounts; promote consistent Terraform and application changes across accounts. Cloud account setup and billing must be explicitly planned before creation.
- Commit → Actions tests/security gates → build/scan images → ECR → auto dev and smoke → manual staging approval/integration → manual prod approval/blue-green with health check rollback; Argo CD reconciles Git desired state. Define the exact Git promotion and traffic switch mechanism before Phase 9.
- Patch base images with rebuild and Trivy proof; OS/nodes with Ansible and managed node updates; dependencies with Dependabot and re-scan; minimize downtime with promotion and blue-green.
- Prometheus, Grafana, Loki, Alertmanager; health/readiness and structured logs from day one. Later AIOps on queryable metrics/logs/events: anomaly detection, alert-to-runbook draft assistant, log-pattern classification.
- Document a node/AZ failure recovery test and stateful backup/DR. Deliver cloud incident and patching runbooks translating NOC operations to platform ownership.

## Phase checkpoints

0. Repository skeleton, this context file and `docs/PROGRESS.md`.
1. Four polyglot services communicate locally via Compose with service authentication.
2. Optimized multi-stage images and local Kubernetes with NetworkPolicies.
3. Terraform AWS network foundation, multi-account VPCs/subnets/TGW.
4. Ansible VPN and BGP hybrid simulator.
5. Palo Alto VM-Series, cloud security monitoring and Falco.
6. Terraform EKS.
7. GitHub Actions and security gates.
8. Argo CD and External Secrets.
9. Multi-environment promotion and blue-green.
10. Observability stack.
11. Resilience/DR and failure test.
12. Incident and patching runbooks.
13. Future AIOps layer.

## Proposed architecture (Phase 1, not implemented)

Client → Go gateway → FastAPI auth for identity and FastAPI scanner for preliminary checks → Postgres scan record + Redis queue → Node worker → controlled public HTTP(S) target → Postgres result. Design and validate each link during its phase. Nothing is running yet.

## Preflight before further implementation

Confirm the host tools and available RAM/CPU for Compose and local Kubernetes; repository access and GitHub Actions usage; authorized scan targets (start with an owned local test endpoint); the SaaS tenant model (individual accounts first or organizations); and the browser UI's auth expectations. Check AWS account billing status and a small spend ceiling before cloud work. Do not enable an external reputation provider, paid security service, or outbound cloud workload until its terms and cost are reviewed. Record test evidence and remaining gaps in PROGRESS.

## Verified implementation status

Phase 1 has started. The first verified component is a Go gateway running as a non-root user in a minimal scratch container. It exposes only `127.0.0.1:8080` locally and provides `GET /health`. No authentication, scan submission, queue, database, scanner, or worker has been implemented yet.
