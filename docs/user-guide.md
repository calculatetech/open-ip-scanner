# User guide

Open IP Scanner discovers devices on authorized IPv4 networks. It combines
local adapter identity, ICMP echo, selected TCP ports, the Linux neighbor
cache, DNS, and mDNS evidence. A device can ignore one or more probes and still
appear through another supported discovery method.

## Install and start

On Debian-family systems, change to the directory containing the single
downloaded package and install it with:

```bash
sudo apt install ./open-ip-scanner_*_amd64.deb
open-ip-scanner
```

A source build can be installed for the current user with:

```bash
cmake --preset release
cmake --build --preset release
cmake --build --preset release --target install-local
~/.local/bin/open-ip-scanner
```

All generated source-build output stays beneath the disposable `build/`
directory. The directly runnable developer binary is always
`build/dev/open-ip-scanner` after building the `dev` preset.

The runtime requires `ping` from `iputils-ping` and `ip` from `iproute2`.
Install and start `avahi-daemon` for mDNS hostname enrichment.

## Choose targets and an adapter

Enter one or more comma-separated targets as CIDR, a full range, a short
range, or a single IPv4 address:

```text
192.168.1.0/24
10.0.0.10-10.0.0.50
10.0.0.10-50
10.0.0.20
```

At most 4,096 unique addresses can be scanned at once. Auto Select chooses the
connected adapter whose route matches the targets. The Auto button generates
targets from connected routable networks using the preferred CIDR/range format
selected in Settings. Select an adapter explicitly when overlapping routes or
VPNs make the automatic choice ambiguous.

Scan only networks you own or are authorized to test. The application asks for
confirmation before the first scan.

## Accuracy, performance, and the upper bound

Performance controls the number of hosts probed concurrently. Accuracy changes
the per-probe attempts and timeouts:

| Mode | Ping | TCP port | Neighbor confirmation |
| --- | --- | --- | --- |
| Fast | 1 attempt, 1 s | 1 attempt, 350 ms | No wait |
| Balanced | 2 attempts, 1 s | 2 attempts, 750 ms | Up to 5.5 s |
| High | 3 attempts, 2 s | 3 attempts, 1.25 s | Up to 6.5 s |
| Maximum | 4 attempts, 3 s | 4 attempts, 2 s | Up to 8 s |

Higher modes give intermittent, sleeping, or slow devices more opportunities
to respond. The status-bar upper bound is a conservative scheduling estimate
derived from target count, worker count, and the per-target deadline. It is not
a countdown or a claim that the scan will take that long. Stop cancels active
work cooperatively; process and socket cleanup may take a short additional
interval.

## Read and use results

Results appear progressively in address order without re-sorting the table or
moving the anchored viewport as enrichment arrives. The table stays concise:
the preferred hostname omits an adapter DNS suffix, except that `.local` mDNS
names remain intact. Select a row to see alternate names and short evidence
sources in Details.

A successful TCP connection proves that a port is open. It does not prove the
service. Unverified ports are labeled `Unknown:<port>`; a service name appears
only after a bounded supported protocol check succeeds. Configured actions can
open a verified or selected service in an external program.

Find searches IP, MAC, vendor, preferred and alternate hostnames, OUI prefixes,
verified services, and observed ports. Filtering and late enrichment preserve
the result order, selection, and scroll position. CSV export is atomic and
escapes spreadsheet-formula prefixes. Printing includes every result row and
the currently visible columns, regardless of the active Find filter. Review
the complete results before printing if the filtered view contains sensitive
information.

## Diagnose missing names or devices

Use Help > Diagnostics to inspect local capability and failure counts with
remediation. A saved support bundle omits targets, hostnames, service payloads,
and raw error text. Optional local diagnostic logging is disabled by default
and can be enabled in Settings > Diagnostics.

For mDNS problems:

1. Confirm `avahi-daemon` is installed and running.
2. Confirm the selected adapter supports multicast and is the adapter that can
   reach the target.
3. Allow mDNS/UDP 5353 on the local link in the host firewall.
4. Check Diagnostics for daemon unavailable, timeout, interface mismatch, or
   malformed-response counts.
5. Remember that not every device publishes a reverse mDNS name.

Fast mode can miss a device that ignores ICMP, has no enabled open service, and
has not populated a confirmable neighbor entry. Retry with High or Maximum,
enable only relevant service ports, and verify the adapter and target range.
See [known limitations](known-limitations.md) before treating absence as proof
that an address is unused.

## Privacy and retained data

Target history is off by default. Settings can enable local target history,
optionally restore the last target at startup, and clear saved targets. During
migration to the current settings schema, legacy target history is removed
unless the earlier remember-last preference explicitly opted into retention.

The in-memory diagnostic ring is bounded. Optional logs are owner-only,
rotating local files under the platform application-data directory. See
[security and privacy](security.md) for the complete boundary.

## Upgrade and uninstall

Upgrades preserve compatible application settings and run privacy-preserving
schema migration at startup. Package upgrades use the distribution package
manager. A local source install can be removed with:

```bash
cmake --build --preset release --target uninstall-local
```

That target removes only known Open IP Scanner files under `~/.local` and
refreshes the same desktop caches used by local install. Generic uninstall uses
the last atomic install-state manifest from that build tree. Do not reuse a
build tree to uninstall a different installation.
