# Embedded vendor assignment data

Open IP Scanner derives its embedded MAC-vendor snapshot from the IEEE
Registration Authority public listings:

- MA-L: <https://standards-oui.ieee.org/oui/oui.csv>
- MA-M: <https://standards-oui.ieee.org/oui28/mam.csv>
- MA-S: <https://standards-oui.ieee.org/oui36/oui36.csv>

IEEE describes these files as its downloadable public listings. Open IP Scanner
is not affiliated with or endorsed by IEEE. The application uses only assignment
prefixes and organization names for local vendor lookup; organization addresses
are not included in `oui.tsv`.

`oui-manifest.json` records the retrieval time, source URLs, row counts, and
SHA-256 checksums for the raw, compressed, and generated data. The compressed
CSV files under `ieee/` are deterministic source snapshots. If IEEE publishes a
duplicate assignment, generation retains the first published row and records the
number of ignored duplicate rows in the manifest.

To retrieve a current snapshot:

```sh
python3 tools/update_oui.py --update
```

To regenerate and verify without network access:

```sh
python3 tools/update_oui.py --offline
python3 tools/update_oui.py --offline --check
```
