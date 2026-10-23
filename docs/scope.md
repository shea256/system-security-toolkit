# Scope and reusable audit material

The initial implementation is intentionally limited to tools that can be reviewed without the original operator's machine state.

| Original material | Decision |
| --- | --- |
| System CA fix and TLS probes | Generalized as the eMudhra macOS tool |
| BIND inventory checks | Read-only inventory; no vulnerability verdict or automatic patching |
| Desktop staging signature checks | Extracted an existing-app verifier requiring explicit expected identity |
| Desktop download/staging scripts | Not copied: hard-coded app versions, download hashes and machine paths |
| Homebrew wrappers | Not copied: depend on local trust configuration or simply invoke Homebrew |
| Node, Python, Go and Electron version checks | Future candidates once advisory mapping, vendor backports and embedded-runtime scope are handled |
| Update authentication workflow | General guidance, not an unreviewed auto-updater |
| Mobile backup comparison | Outside security remediation scope |
| Inventories, reports, logs and patch results | Private operator evidence; excluded |
| Binaries, wheels, archives, caches and rollback folders | Excluded |
| Local CA bundles, environment files and curl configuration | Excluded; runtime configuration is not portable |

Linux requires distribution-specific paths, trust-store tooling and tests. Do not run the macOS fix on Linux or add empty platform folders that imply support.

Future tools should provide an explicit scope, dated primary sources, safe defaults, clear failure results, and tests for their actual side effects. Favor vendor-supported updates over custom package installers.
