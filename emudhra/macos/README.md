# eMudhra: macOS PEM trust-bundle mitigation

This temporary workaround removes three explicitly identified TLS root public keys from `/private/etc/ssl/cert.pem`. It addresses clients using this file, including the Apple curl/Git paths tested locally. It does not modify Keychains, Apple's revocation service, or application-specific root bundles.

The compromised keys belonged to **intermediate CAs**, not these root CAs. Removing an issuing root blocks other valid chains too. In particular, removing AAA Certificate Services can break legitimate services. Review this tradeoff; managed machines should follow their administrator's policy. Keep installing OS updates and reassess the workaround as vendors ship fixes.

## Inspect, apply, verify

Run from the repository root. The first command is offline and changes nothing:

```sh
/usr/bin/python3 -I -S emudhra/macos/fix_system_ca.py
```

Review the named keys. If you choose to apply the workaround:

```sh
sudo /usr/bin/python3 -I -S emudhra/macos/fix_system_ca.py --apply
```

The tool validates every certificate, requires at least 100 retained certificates, saves an exclusive root-owned backup beside `cert.pem`, and atomically replaces the file. It preserves ownership and mode, rejects symlinks/hardlinks and unsafe permissions, and stops if the original changes. A lock prevents concurrent instances of this tool; it cannot coordinate unrelated privileged writers. An applied bundle is normalized to PEM certificate blocks; text annotations are omitted. An already-filtered bundle is left byte-for-byte unchanged.

It does not download any certificates, packages, or code. Do not install new trust anchors from an unverified source to bootstrap this operation.

Then opt into network verification:

```sh
/usr/bin/python3 -I -S emudhra/macos/verify_tls.py --network
```

This contacts four researcher-operated `*-emudhra.we-have-a-problem.com` test hosts plus GitHub as a working-HTTPS control. Those servers receive normal connection metadata. It makes HEAD requests with curl and unauthenticated `git ls-remote` requests; response bodies are never executed. It ignores user CA/proxy environment overrides and curl/Git configuration. This isolates the built-in tools' default trust behavior; it does not reproduce a corporate proxy or custom CA setup.

| Result | Meaning |
| --- | --- |
| `rejected` | Tested chain failed with an issuer or revocation error |
| `accepted` | TLS succeeded against a researcher test endpoint |
| `inconclusive` | Timeout, DNS failure, expiry, unexpected output or another error |
| `control_ok` | Ordinary HTTPS control succeeded |

Verifier exit codes: 0 means every test chain was rejected and controls passed; 1 means at least one affected endpoint was accepted; 2 means at least one result was inconclusive and none was accepted. Endpoint behavior can change. Tests do not cover all compromised intermediates, all applications, every possible chain, or historical exploitation.

Mitigation script exit codes: 0 means no listed keys remain or a requested operation completed; 1 means dry-run found listed keys; 2 means invalid input or a stopped operation. An error after replacement (for example a directory-sync failure) requires checking the current bundle; do not assume an error means nothing changed.

## Restore

Restoring reintroduces the original trust. Use the exact backup path printed by this tool:

```sh
sudo /usr/bin/python3 -I -S emudhra/macos/fix_system_ca.py --restore /private/etc/ssl/cert.pem.sst-backup-REPLACE_WITH_ID --acknowledge-restored-trust
```

Restore is permitted only when the current bundle exactly matches the filtered contents of that root-owned backup. It refuses to overwrite a subsequent vendor update or unrelated change, and backs up the current file before restoring. Backups from the earlier private audit script are not accepted by this interface. Do not manually restore an old bundle over a newer OS bundle just to undo this workaround.

**Recheck after OS updates.** Local tests observed that both 26.7.1 and 27.0.1 restored the original bundle after an earlier manual mitigation. This is an observation on one Mac, not an exhaustive claim about all installations or native Apple trust paths.

## Pinned root keys and sources

The list was reviewed October 23, 2026. Hashes are SHA-256 of DER SubjectPublicKeyInfo, not hashes of entire certificates.

| Root | SPKI SHA-256 |
| --- | --- |
| AAA Certificate Services | `bd153ed7b0434f6886b17bce8bbe84ed340c7132d702a8f4fa318f756ecbd6f3` |
| emSign ECC Root CA - G3 | `8d417db2dd8bf5e3084d1e3f196d583849d81bdd4c00c70b9d39369e96b8c782` |
| emSign Root TLS CA - G3 | `c619e4780ed8e0abeda24ad732567de4383a7ea941338f6d1a7d1b49ac792fe9` |

The third root was absent from the tested Apple bundle. It is included defensively for TLS bundles containing that key. This tool does not address the separate code-signing trust hierarchy.

- [Mozilla's CA incident investigation](https://bugzilla.mozilla.org/show_bug.cgi?id=2083449): primary incident record.
- [Researcher-maintained incident site](https://emudhra.we-have-a-problem.com/): test hosts, macOS workaround and limitations. Community documentation, not an Apple advisory.
- [Root certificate inventory](https://emudhra.we-have-a-problem.com/roots.json): public certificates and key hashes.
- [Incident site's source repository](https://github.com/galadran/we-have-a-problem.com): inspectable implementation and history.

The public PEM fixtures in `tests/fixtures/` come from that root inventory. Tests recompute their SPKI hashes. No private keys, personal audit reports, or customer certificates are included.
