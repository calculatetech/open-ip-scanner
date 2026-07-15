# Known limitations

- Version 1.0 is scoped to Linux x86-64, IPv4, and Qt 6.4 or newer. Windows,
  macOS, ARM, Qt 5, and IPv6 scanning are not supported.
- A scan accepts at most 4,096 unique IPv4 targets. This prevents accidental
  unbounded work; split larger authorized inventories into smaller ranges.
- Device absence is not proof that an address is unused. Firewalls, power
  saving, rate limiting, VLAN boundaries, wireless isolation, and devices that
  ignore the enabled probes can all hide a device.
- The upper bound shown in the pre-scan confirmation for a large scan is a
  conservative scheduling estimate, not a completion prediction. Actual
  duration depends on early responses, concurrency, enabled ports,
  cancellation, and local resolver/process timing.
- Fast accuracy intentionally favors a quick lay of the land and can miss slow
  or sleeping devices. Higher accuracy repeats probes and waits longer but
  increases traffic and elapsed time.
- MAC/vendor evidence normally requires a same-link neighbor entry and is not
  expected through a routed network. Private/randomized MAC addresses cannot
  be mapped reliably to a public vendor.
- mDNS hostname enrichment requires a running Avahi daemon, multicast support
  on the selected adapter, and local firewall allowance. Many devices publish
  no reverse mDNS name. DNS-SD service browsing is not implemented.
- PTR, system-resolver, local, and mDNS sources can disagree. The details pane
  preserves useful alternatives, while the table chooses one concise preferred
  name and normally omits the adapter DNS suffix.
- An open TCP port is shown as `Unknown:<port>` unless a supported bounded
  protocol check verifies the service. Port convention alone is never treated
  as service identity, and the scanner does not identify operating systems.
- Results populate progressively in address order. Enrichment does not
  re-sort or move the viewport; an explicit user sort is applied as a deliberate
  table action.
- Duplicate-IP conflict detection, persistent subnet identity history, DNS-SD
  discovery, localization, other package formats, and additional platform
  backends are post-1.0 roadmap items.
- Kubuntu 26.04 passed the complete release-candidate desktop qualification.
  Other distributions and future desktop-stack versions are not implied by
  that result or by the Ubuntu/Debian automated matrix.
