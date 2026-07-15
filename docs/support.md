# Support

Open IP Scanner is supported for the environment and boundaries in the
[platform support contract](platform-support.md). Review the
[user guide](user-guide.md) and [known limitations](known-limitations.md)
before reporting a defect.

## Ask for help or report a bug

Use the repository's
[GitHub issues](https://github.com/calculatetech/open-ip-scanner/issues) for
non-sensitive bugs and support requests. Search existing issues first and
include:

- the Open IP Scanner version from Help > About;
- the Qt runtime and architecture from Help > About;
- the Linux distribution and desktop environment;
- the selected accuracy mode and whether the problem reproduces with a single
  authorized `/32` target;
- concise reproduction steps and the expected and observed behavior;
- relevant capability/failure counts or a redacted support bundle from
  Help > Diagnostics.

Do not post internal target ranges, device names, MAC addresses, credentials,
service payloads, raw logs, or an unreviewed screenshot publicly. The default
support bundle is designed to omit targets, hostnames, payloads, and raw error
text, but review every file before sharing it.

For a suspected security vulnerability, do not open a public issue. Follow the
private process in [security.md](security.md).

## Support boundary

The project can investigate reproducible behavior on the declared Linux
x86-64/IPv4/Qt 6.4+ contract. Unsupported operating systems, architectures,
Qt 5, IPv6 scanning, downstream repackaging changes, and third-party network
or firewall configuration are not release-qualified. Useful reports from those
environments are welcome, but they are not compatibility commitments.
