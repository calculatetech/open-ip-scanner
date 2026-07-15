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
