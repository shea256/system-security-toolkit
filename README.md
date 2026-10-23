# System Security Toolkit

Tools to audit, mitigate, and verify system and developer-tool security vulnerabilities.

**Private development preview. Currently supports macOS.** There is no Linux remediation implementation yet. Tools have separate scopes; this is not a comprehensive vulnerability scanner or a guarantee that a machine is secure.

| Tool | Purpose | Changes |
| --- | --- | --- |
| [eMudhra macOS mitigation](emudhra/macos/README.md) | Inspect and filter the system PEM trust bundle; backup, restore and TLS probes | Dry-run by default; explicit `--apply` or `--restore` writes the bundle |
| [BIND inventory](checks/bind_macos.py) | Look for a local `named` server in standard locations, services and processes | Read-only |
| [App signature verifier](verification/app_signature_macos.py) | Check an existing app against an expected publisher and bundle identifier | No installation or launch; Gatekeeper may contact Apple |

## Start here

Read the source and the tool's documentation before running it. Use Python 3.9 or newer. macOS may require Apple Command Line Tools for `/usr/bin/python3` and Git. No Python packages are required. Download and inspect a reviewed revision; do not pipe a network response into a privileged shell.

From the repository root:

```sh
/usr/bin/python3 -I -S emudhra/macos/fix_system_ca.py
/usr/bin/python3 -I -S checks/bind_macos.py
```

The first command returns exit status 1 when listed root keys remain; that is a finding, not a failed execution. See its [instructions](emudhra/macos/README.md) before applying anything.

To inspect an already-downloaded application, substitute its actual path and independently established expected publisher identifiers:

```sh
/usr/bin/python3 -I -S verification/app_signature_macos.py "/path/to/Example.app" --team-id EXPECTEDID --bundle-id com.example.app
```

The app checker does not download, install, quit or launch applications. A valid signature identifies a signer and checks integrity; it does not prove that an app has no vulnerabilities. A checksum obtained through the same compromised channel as a download is not independent authentication. See [update verification](docs/update-verification.md).

## BIND inventory limits

`checks/bind_macos.py` lists evidence, not a vulnerable/safe verdict. It does not search containers, VMs, remote DNS servers, or every custom install path. Unprivileged process/socket visibility can be incomplete. Apple's `dig` client is not the `named` server. An old displayed version alone does not account for vendor backports.

The October 21, 2026 [ISC release announcement](https://lists.isc.org/pipermail/bind-announce/2026-October/001306.html) links the relevant advisories and identifies stable release 9.20.30. Follow the applicable vendor advisory if a server is found; this toolkit does not upgrade or reconfigure it.

## Development and review

```sh
python3 -I -S -m unittest discover -s tests -v
```

Tests use temporary files and public certificate fixtures. They never modify the system trust bundle. The system-writing entry point refuses non-macOS platforms; portable test execution is not Linux support. See [validation](docs/validation.md) for the distinction between original local mitigation evidence and this packaged implementation.

Keep results in ignored `local-results/` if needed. Review output before sharing: paths, installed software and process details can be identifying. Do not commit machine inventories, credentials, local trust overrides, downloads, caches, or rollback app copies. See [scope and candidates](docs/scope.md).

No release has been published. Do not treat this preview as an independently audited security product.
