# Verifying updates

Updating through a client that still accepts compromised certificate chains can expose the update download to impersonation. First establish a trustworthy update path, or independently authenticate the artifact before executing it. This toolkit does not promise immunity from every MITM or supply-chain attack.

For macOS apps, the included verifier checks code-signature integrity, an explicitly expected Developer ID team and bundle identifier, and Gatekeeper's execution assessment. Obtain expected identities from an independently trusted vendor source or a previously authenticated installation. Taking the expected signer from the same untrusted download proves nothing about the intended publisher.

A checksum proves equality to the referenced digest, not its publisher. Prefer authenticated release signatures with an independently established signing key where available. A digest downloaded alongside the artifact over the same compromised connection is not independent evidence.

Do not disable TLS verification, accept arbitrary new roots, remove quarantine to get around a failed assessment, or run an installer merely because its download succeeded. Signature verification also does not establish that a particular app version or embedded runtime contains a vulnerability fix. Check vendor advisories separately.

The verifier assesses an existing app; it does not install updates, stop applications, select trusted publishers for you, or modify Conductor-managed binaries.
