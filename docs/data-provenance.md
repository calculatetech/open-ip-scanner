# Data provenance

Open IP Scanner performs vendor lookup locally using a committed snapshot of
the IEEE Registration Authority public MA-L, MA-M, and MA-S listings:

- <https://standards-oui.ieee.org/oui/oui.csv>
- <https://standards-oui.ieee.org/oui28/mam.csv>
- <https://standards-oui.ieee.org/oui36/oui36.csv>

The generated lookup contains assignment prefixes and organization names. It
does not include the organization addresses published in the source listings.
Open IP Scanner is not affiliated with or endorsed by IEEE.

`data/oui-manifest.json` is the machine-readable provenance record. It stores
the retrieval timestamp, source URLs, row counts, duplicate dispositions, and
SHA-256 hashes for the downloaded, deterministic compressed, and normalized
files. `data/oui.tsv` is generated in longest-prefix-compatible order and is
embedded in the application. Builds and normal CI never download vendor data.

Maintainers update and then independently reproduce a snapshot with:

```bash
python3 tools/update_oui.py --update
python3 tools/update_oui.py --offline --check
```

The offline check must reproduce the normalized data byte for byte from the
committed source snapshots. Custom user OUI entries remain local settings and
take precedence over built-in entries of the same prefix length. Locally
administered/private MAC addresses are labeled private/randomized instead of
being assigned a public vendor.

The installed Debian copyright file records the application license, IEEE
source URLs and usage, and the external Avahi relationship. The current
snapshot date is visible in Help > About.

## Release artifacts

The Release gate builds the Debian package twice in separate clean build
directories with one audited `SOURCE_DATE_EPOCH` and requires identical
SHA-256 hashes. It checks the installed binary for position independence,
stack protection, fortified library calls, read-only relocations, immediate
binding, and x86-64 control-flow protection. Configure-time checks reject a
toolchain that cannot apply the required stack-clash and hardening flags.

The same gate creates a deterministic source archive, `SHA256SUMS`, and an
SPDX 2.3 JSON document. The SBOM identifies the Debian package by SHA-256 and
lists every installed regular file with SHA-1 and SHA-256 checksums. License
fields remain `NOASSERTION` where one expression cannot truthfully cover the
application, IEEE-derived vendor data, and external runtime components.

The dormant 1.0 workflow in `.github/workflows/release-artifacts.yml` accepts
only version `1.0.0` from a clean checkout. When separately authorized at the
release candidate, it uses GitHub's keyless OIDC identity to attest the package,
source archive, checksums, and SBOM. The ordinary pre-1.0 CI artifact is a test
bundle, not a signed release.
