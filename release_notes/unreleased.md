**Unreleased**

* Updated connector development tooling.
* Enabled TLS certificate verification by default for new assets. [PAPP-38210, PSAAS-30847]
* Advance the poll checkpoint only after every selected scan is durably ingested, and surface failed scans for retry. [PAPP-38210, PSAAS-31767, PSAAS-32193]
* Bound API pagination even when an action has no caller-supplied result limit. [PAPP-38210, PSAAS-32228]
