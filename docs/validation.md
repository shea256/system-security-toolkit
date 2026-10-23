# Validation record

## Original local mitigation

On one Mac, the earlier private script removed the identified keys from the system PEM bundle. After updates to macOS 26.7.1 (25G241) and 27.0.1 (26A434), the bundle again contained the affected keys. The 27.0.1 bundle was byte-identical to the pre-mitigation bundle retained from the earlier audit.

On 27.0.1, Apple curl accepted four researcher test endpoints before reapplication, then rejected all four with issuer errors afterward. Apple Git accepted both tested chain variants before reapplication, then rejected them with issuer errors afterward. Both tools connected to GitHub as a control before and after. Tests cleared CA overrides; TLS verification remained enabled.

These are observations from one machine. The private raw records remain with the operator and are not committed here. They validate the mitigation approach, not every path in the packaged rewrite.

## Packaged implementation

The unit suite exercises real public-key fingerprints, exact filtering, idempotence, malformed-input rejection, dry-run, platform/privilege guards, backup/restore, changed-file detection, failed replacement and network-result classification. Filesystem tests operate only in temporary directories.

Recorded October 23, 2026. All 15 unit tests passed on Amazon Linux (Python 3.9) and macOS 27.0.1. The Mac smoke tests below passed without changing the system PEM bundle, confirmed by comparing its SHA-256 before and after. No system-changing packaged apply/restore test has yet been performed on a disposable Mac. The original private script's successful operation is not a substitute for that test.

| Check | Status |
| --- | --- |
| Unit tests | 15 passed on Linux and macOS; temporary-file replacement and restore included |
| Packaged macOS dry-run | Passed: 126 certificates, no listed keys remaining |
| Packaged macOS TLS verifier | Passed: curl and Git rejected all four test hosts; both GitHub controls succeeded |
| Packaged BIND inventory | Completed; no server evidence found in inspected locations. One unrelated launch plist was unreadable and reported as an inspection error |
| Packaged app verifier | Passed on an existing Chrome installation with independently established publisher/bundle IDs |
| Packaged privileged apply/restore on disposable macOS | Not performed |
| Independent security review | Not performed |
| Linux implementation | Not implemented |
