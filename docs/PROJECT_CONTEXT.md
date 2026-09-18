# URL Threat Scanner — Project Context
## Product
A user submits a URL. The platform checks it and returns a threat verdict with scan history.
## Starting point
Phase 0 is in progress. No application code has been built or tested.
## First security rule
Treat every submitted URL as untrusted. The scanner must not be able to contact private networks, local services, or cloud metadata endpoints.
## Scan flow
Submitting a URL returns a scan ID immediately. A background worker performs the scan, saves the result, and the user checks the ID for the verdict.
