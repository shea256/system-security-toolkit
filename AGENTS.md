# Working on this toolkit

- Keep the repository private until the owner explicitly approves publication.
- Work on branches and use PRs once a base branch exists. Do not merge without an explicit request.
- Keep machine reports, credentials, caches, downloads and rollback artifacts out of Git.
- Each tool must state its platforms, scope, side effects and evidence limits. Linux tests do not imply Linux remediation support.
- Remediation defaults to inspection. Require explicit flags for changes; provide backups and guarded restore where applicable.
- Never disable TLS verification, run downloaded code as part of a check, or call a network failure a successful security test.
- Attribute advisories to primary sources and record verification dates. Do not infer runtime exposure solely from dependency names or version strings.
- Test malformed inputs and failure behavior for privileged file edits. Run tests in temporary directories; do not use a real system trust store as a write-test fixture.
- Do not add a broad automatic updater or hard-coded personal app inventory.
