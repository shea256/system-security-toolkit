# Validation record

## Original local mitigation

On one Mac, the earlier private script removed the identified keys from the system PEM bundle. After updates to macOS 26.7.1 (25G241) and 27.0.1 (26A434), the bundle again contained the affected keys. The 27.0.1 bundle was byte-identical to the pre-mitigation bundle retained from the earlier audit.

On 27.0.1, Apple curl accepted four researcher test endpoints before reapplication, then rejected all four with issuer errors afterward. Apple Git accepted both tested chain variants before reapplication, then rejected them with issuer errors afterward. Both tools connected to GitHub as a control before and after. Tests cleared CA overrides; TLS verification remained enabled.

These are observations from one machine. The private raw records remain with the operator and are not committed here. They validate the mitigation approach, not every path in the packaged rewrite.

## Packaged implementation

The unit suite exercises real public-key fingerprints, exact filtering, idempotence, malformed-input rejection, dry-run, platform/privilege guards, backup/restore, changed-file detection, failed replacement and network-result classification. Filesystem tests operate only in temporary directories.

Recorded October 23, 2026. All 15 unit tests passed on Amazon Linux (Python 3.9) and macOS 27.0.1. The Mac smoke tests below passed without changing the system PEM bundle, confirmed by comparing its SHA-256 before and after.

The [first CI run](https://github.com/shea256/system-security-toolkit/actions/runs/39979103605) passed on commit `cae699ee68a1a94a4680dafc6c08258ae876ca09`. Its disposable macOS runner reported macOS 26.6.2, build 25G83 (image `macos-26-arm64`, 20261013.0424.1). Both the 15 unprivileged unit tests and all 5 privileged integration tests passed. Linux CI also passed the 15 unit tests.

The privileged suite redirects only the target constant to a root-owned temporary fixture. It runs the real platform, ownership, parent-directory, locking, apply, backup and restore code as root. It checks idempotence and refuses subsequent-file changes, symlinks, untrusted ownership and an already-held lock. A before/after hash assertion confirms that the runner's live system bundle is unchanged. This exercises privileged file operations on a disposable Mac, not an end-to-end change to a live system trust store.

| Check | Status |
| --- | --- |
| Unit tests | 15 passed on Linux and macOS; temporary-file replacement and restore included |
| Packaged macOS dry-run | Passed: 126 certificates, no listed keys remaining |
| Packaged macOS TLS verifier | Passed: curl and Git rejected all four test hosts; both GitHub controls succeeded |
| Packaged BIND inventory | Completed; no server evidence found in inspected locations. One unrelated launch plist was unreadable and reported as an inspection error |
| Packaged app verifier | Passed on an existing Chrome installation with independently established publisher/bundle IDs |
| Packaged privileged apply/restore on disposable macOS | 5 integration tests passed on root-owned temporary fixtures; live trust store unchanged |
| Independent security review | Not performed |
| Linux implementation | Not implemented |
