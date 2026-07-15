# Security and privacy

Open IP Scanner is an active network tool. Use it only on networks you own or
have explicit authorization to test. A scan can generate ICMP echo requests,
TCP connections to enabled ports, bounded HTTP/TLS/SMTP/banner exchanges,
local neighbor-cache reads, and DNS/mDNS lookups. Accuracy and worker settings
increase attempts and concurrency; start conservatively on fragile networks.

The application does not provide authentication, vulnerability assessment,
credential testing, stealth, or proof that an undiscovered address is unused.
External service actions run only the configured local program and arguments;
review those settings before use.

## Report a vulnerability privately

Do not open a public issue for a suspected vulnerability or include sensitive
network evidence in a public discussion. GitHub private vulnerability
reporting is not currently enabled for this repository. Email the upstream
security contact at `mikebeutler84@gmail.com` with:

- a concise description and affected version;
- reproduction steps using non-sensitive test data where possible;
- impact and any known mitigations; and
- a safe way to follow up.

Do not send credentials, production packet captures, or complete internal
inventories unless the maintainer explicitly requests a protected transfer
method. Allow time for triage and coordinated correction before disclosure.
Non-sensitive defects belong in the public support process in [support.md](support.md).

## Local data boundary

Target history is disabled by default. If enabled, targets and the optional
last input are stored through the desktop settings backend and can be cleared
from Settings. Privacy migration removes legacy target data unless an earlier
remember-last choice explicitly opted into retention.

Diagnostics keep a bounded in-memory event ring. Default support export omits
targets, hostnames, service payloads, and raw error text. Optional diagnostic
logging is disabled by default; when enabled it writes owner-only rotating
files in the application-data directory, with three files limited to about
one MiB each. Logs and exports remain local until the user chooses to share
them. Always inspect them first.

CSV export treats formula-leading values as data, writes atomically, and never
transmits the file. Vendor lookup uses the embedded offline snapshot; normal
builds and scans do not fetch OUI data from IEEE.

## Release integrity

Until the release-candidate provenance workflow is complete, treat CI package
artifacts as test artifacts rather than a signed release. The required signing,
SBOM, checksum, provenance, and verification steps are tracked in
[release-checklist.md](release-checklist.md).
