# Software Release Verification Tool
*Project 18 · PKI and trust services · Classes A, B and C*

Validates a downloaded software package against a publisher-signed manifest and a local trust store **before installation**. Any failure blocks the install.

## Layout
| File | Role |
|---|---|
| `core.py` | Shared core: manifest, signing, trust store, `verify_release()` pipeline |
| `relverify.py` | **Class A** CLI (also `keygen`, `sign`, `trust-add`, `trust-revoke`, `update`, `gui`) |
| `gui.py` | **Class B** Tkinter desktop verifier, trust records, trust-on-first-use prompt |
| `updater.py` | **Class C** update client: rollback protection, atomic install |
| `demo.py` | Mandatory tamper demonstration (all classes) |
| `class_demo.py` | Guided press-Enter demo for presenting (14 steps) |
| `sbom.py` | SBOM verification (CycloneDX / SPDX) and offline advisory scan |
| `translog.py` | Transparency log: Merkle tree, signed tree heads, inclusion and consistency proofs |
| `tufmeta.py` | TUF-style metadata: root, targets, snapshot, timestamp, thresholds, key rotation |
| `signers.py` | Hardware-key (PKCS#11 / HSM) signer interface |
| `.github/workflows/ci.yml` | CI: tests on Python 3.10-3.13, Linux and Windows, plus ruff and bandit |
| `stress_test.py` | 11,000 randomized attack trials with timing and an Ed25519/RSA benchmark |
| `tests/test_adversarial.py` | Adversarial pack: filesystem attacks, crash recovery, locks, audit policy, parser fuzzing |
| `tests/` | 174 tests (124 functional + 50 adversarial) (`python3 -m unittest discover -s tests`) |
| `docs/demo_output.txt` | Captured output of `demo.py` |

Requires Python 3.10+ and `pip install -r requirements.txt`. Tkinter is needed only for Class B.

## Design
**Release manifest** (JSON, signed as canonical JSON: sorted keys, no whitespace):
`package, publisher, version, sha256, key_id, timestamp, expiry`. The file on disk is an envelope: `{manifest, alg, signature[, public_key]}`. `public_key` is only used for first-use prompts and is never trusted by itself.

**Signatures:** Ed25519 or RSA-PSS (SHA-256, MGF1-SHA256, digest-length salt, 3072-bit keys).

**Trust store** (`trust.json`): one record per publisher: `name, key_id, alg, public_key, fingerprint, not_before, not_after, revoked`. `key_id` is the first 16 hex chars of the SHA-256 of the DER public key; `fingerprint` is the full hash. On load, each record's fingerprint is rechecked against its key, so a swapped key is detected.

**Verification order** (`verify_release`):
1. Parse and validate the manifest schema
2. Signature verifies against the trust-store key named by `key_id`
3. Key is not revoked and is within `not_before`..`not_after`
4. Manifest has not expired
5. *(C)* Version is strictly newer than the installed version
6. SHA-256 of the package equals the manifest hash

Signature comes before hash on purpose: the hash is only believed once the manifest it lives in is authentic. Unexpected errors (missing file, bad JSON, corrupt trust store) also block (fail closed).

## Usage
```bash
python3 relverify.py keygen --out acme                       # acme.key (private), acme.pub
python3 relverify.py trust-add --trust-store trust.json --pub acme.pub --name "Acme"
python3 relverify.py sign --pkg app.tar.gz --key acme.key --publisher Acme --version 1.0.0 --out app.json
python3 relverify.py verify --pkg app.tar.gz --manifest app.json --trust-store trust.json   # exit 0 = install
python3 relverify.py update --pkg app.tar.gz --manifest app.json --trust-store trust.json \
        --state state.json --install-dir ./installed                                        # Class C
python3 relverify.py gui                                                                    # Class B
```
Exit codes: `0` verified, `1` blocked, `2` usage error.

## Class details
- **A:** CLI above; `-q` prints only the verdict.
- **B:** GUI shows the step-by-step log and a table of publisher trust records with a Revoke button. **TOFU:** for an unknown key whose manifest embeds a public key, the signature is checked first, then the user sees publisher, key ID and fingerprint and decides. Accepting writes a trust record (default 1-year validity). Users should confirm the fingerprint out-of-band.
- **C:** `state.json` records the installed version per package. Offered versions must be strictly greater (compared numerically, so `1.10.0 > 1.9.0`). Expired signing keys are rejected via `not_after`, and altered manifests via the signature. Install copies the file, re-hashes the copy (TOCTOU guard), then updates state atomically; a failed update leaves state untouched.

## Threat model
| Attack | Defence | Demo step |
|---|---|---|
| Modified package | SHA-256 mismatch | A3 |
| Modified manifest (incl. fixing the hash) | Signature fails | A4, C5 |
| Attacker's own key | Not in trust store | A5 |
| Compromised/retired key | Revocation flag, `not_after` | B3, C3 |
| Replay of old signed release (downgrade) | Version must increase | C2 |
| Stale manifest | `expiry` | C4 |
| Swapped key in trust store | Fingerprint recheck on load | unit test |

## Version 2 improvements
| Improvement | What it fixes |
|---|---|
| **Signed revocation lists** (`revoke-list`, `--revocation-list`) | Revocation no longer depends on a hand-set local flag. A trusted authority signs a list of revoked key IDs; the list has an expiry and a number that may only increase, so an attacker cannot replay an old list to un-revoke a key. A missing, expired, forged or older list blocks the install (fail closed). |
| **Passphrase-encrypted private keys** (`keygen --passphrase`) | Private keys are no longer stored in plain text. Set `RELVERIFY_PASSPHRASE` for scripts. |
| **Audit log** (`--audit-log FILE`) | One JSON line per decision (time, package, version, publisher, key, allowed or blocked, reason). |
| **JSON output** (`verify --json`) | Machine-readable result for scripts and CI. |
| **`trust-list`** | Shows every publisher in the trust store and whether it is active or revoked. |
| **9 more unit tests** | Revocation list (listed, unlisted, untrusted signer, tampered, expired, rollback, missing), encrypted keys, audit log. |

Example:
```bash
python relverify.py keygen --out authority
python relverify.py trust-add --trust-store trust.json --pub authority.pub --name "Revocation Authority"
python relverify.py revoke-list --key authority.key --number 1 --revoke <KEY_ID> --out crl1.json
python relverify.py verify --pkg app.tar.gz --manifest app.json --trust-store trust.json \
        --revocation-list crl1.json --audit-log audit.log
```

## Version 3 improvements
| Improvement | What it fixes |
|---|---|
| **Delegation certificates** (`delegate`, `sign --chain`) | Only a root key needs to be in the trust store. The root signs short-lived certificates for release keys, so keys can be rotated without re-trusting anything. The verifier walks the chain (up to 3 certificates) to a trusted key, checks every signature and validity window, and uses the intersection of the windows. A forged, expired, mismatched, over-long, or untrusted chain blocks the install. |
| **Revocation covers the whole chain** | A signed revocation list can revoke a leaf key, an intermediate, or the root. A locally revoked root also blocks every release signed under it. |
| **Rollback memory survives a deleted `state.json`** | The update client takes the highest of the state file and the versions actually present in the install folder, so wiping the state file no longer resets rollback protection. |
| **11 more unit tests, 2 more stress scenarios** | Chains (valid, two-level, untrusted root, forged, wrong subject, expired, too long, revoked root/leaf) and the state-wipe attack. Stress test is now 11 scenarios x 1,000 = 11,000 trials. |

Example:
```bash
python relverify.py keygen --out release
python relverify.py delegate --issuer-key acme.key --subject-pub release.pub --name "Release key" --out cert.json
python relverify.py sign --pkg app.tar.gz --key release.key --publisher Acme --version 3.0.0 --out app.json --chain cert.json
python relverify.py verify --pkg app.tar.gz --manifest app.json --trust-store trust.json   # only Acme's root is trusted
```

## Version 3.1: hardening (from a security review)
| Improvement | What it fixes |
|---|---|
| **Path-traversal protection** | Package names are restricted to `[A-Za-z0-9._-]` (max 100), and `.`/`..`, trailing dots and Windows device names (CON, NUL, ...) are rejected. The install destination is also resolved and must be a direct child of the install folder (`safe_dest`). Two independent layers. |
| **Strict manifest schema** (`validate_manifest`) | Exact field set (no extras), every field must be a string, 16-hex key ID, 64-hex hash, ASCII-digit versions (max 10 parts, 9 digits each), expiry must be after the timestamp, manifest file limited to 256 KB. |
| **Signature algorithm enforcement** | The algorithm always comes from the trusted key record, never from the file. A mismatching or unknown `alg`, or any unexpected envelope field, blocks. Same rule for delegation certificates and revocation lists. |
| **Atomic, serialised install** | Copy to a temp file in the install folder, `fsync`, re-hash, then atomic rename; state file is also fsynced. A lock file allows one update at a time. A crash or disk-full error leaves no partial file (tested). |
| **Trust store parsing** | Any malformed store (bad JSON, wrong types, missing fields) or duplicate key ID blocks cleanly instead of crashing. |
| **Hash-chained audit log** | Each record carries the hash of the previous one plus a unique ID, algorithm, package hash and tool version. `audit-verify` detects edited, removed or reordered records. |
| **Revocation freshness policy** | `--max-crl-age DAYS` blocks installs when the revocation list is older than your policy. |
| **Package-scoped delegation** | `delegate --packages "app*"` limits which package names a delegated key may sign; widening the list invalidates the certificate. |
| **Private key files are owner-only (0600)** | `keygen` writes keys with restrictive permissions and warns when no passphrase is used. |
| **Reports and a better GUI** | `--report FILE` and the GUI Export button write a verification report. The GUI gains a colour-coded checklist, package details with Copy buttons, trust-record search, confirmation before revoking, a revocation-list field, and remembers file paths (not run in the build environment, see limitations). |
| **Clean, broader tests** | 54 tests, no ResourceWarnings, including path traversal, schema, interrupted install, lock, audit chain, stale revocation, malformed trust stores, and a 300-trial byte-mutation fuzz test. |

New commands: `audit-verify`, `trust-list`, `delegate --packages`, and options `--max-crl-age`, `--report`, `--package-name`.

## Version 3.2: second security audit
| Finding | Fix |
|---|---|
| **TOFU saved trust before the release was fully verified** (high) | A key the user accepts is now held as a temporary record. It is written to the trust store only after every check (validity, expiry, revocation, rollback, package hash) has passed. A rejected or tampered first release leaves the trust store untouched. |
| **Trust-store validation incomplete** | Every record is checked: object type, all fields present, `revoked` is a real boolean, name type and length, key ID and algorithm match the stored public key, dates parse and the validity period is not empty; revocation numbers must be non-negative integers. |
| **Revocation-list validation incomplete** | Exact field set, `number` must be a real integer (not a string, float or boolean), revoked entries must be 16-hex key IDs or `cert:SERIAL`, at most 10,000 entries, 1 MB file limit, expiry after issue date, signer ID format checked. Creating a list with bad IDs is refused. |
| **Delegation policy too permissive** | Certificates now carry a random serial, so ONE certificate can be revoked (`cert:<serial>`) without revoking the key, and an optional `max_depth` (`delegate --max-depth 0`) forbids sub-delegation. Together with package scope, a delegated key can be limited to what it needs. |
| **Rollback state weak** | `state.json` now records version, SHA-256, key ID and install time per package and is strictly validated (malformed state blocks, old-style state still reads). `installed` command compares every installed file with its recorded hash (ok / MODIFIED / MISSING). Rollback still also looks at the installed files themselves. |
| **Audit failures silently ignored** | A failed audit write now prints a warning, and `--audit-required` makes it a hard failure: no audit record, no install. |
| **Small items** | `atomic_write` removes its temp file on failure; `parse_version` has explicit limits (50 chars, 10 parts, 9 digits each); unknown keys give a clear error; unexpected internal errors print a short message and `--debug` (before the command) shows the full traceback. |

Already covered in 3.1: path traversal, atomic install, strict manifest schema, hash-chained audit log, owner-only key files, and closed file handles.

Not implemented at that point (added in version 4 below): `key_usage` restrictions, SBOM verification, transparency logs, TUF-style metadata, hardware keys. Still not implemented: an authenticated or hardware-backed trust store and state file (a local attacker with write access can still edit both).

## Version 4: supply-chain features
All four are optional plug-in checks that run after the normal six checks, and a release is only accepted (and any state remembered) if **every** check passes.

### 1. Certificate and key usage restrictions (`key_usage`)
Every trusted key and every delegation certificate now says what the key may do: `release` (sign releases), `delegate` (issue certificates), `revocation` (sign revocation lists), `log` (sign transparency tree heads). A key used for the wrong job is rejected, so a stolen revocation key cannot ship software and a leaked release key cannot revoke anyone.
- New certificates default to `release` only (least privilege). Chains are checked per position: the signing key's certificate must allow `release`, every certificate above it must allow `delegate`, and the trust anchor must be allowed to delegate.
- Keys accepted through trust-on-first-use are `release` only. Records created before this feature keep the old defaults (release, delegate, revocation).
```bash
python relverify.py trust-add --trust-store trust.json --pub authority.pub --name Authority --usage revocation
python relverify.py delegate --issuer-key root.key --subject-pub mid.pub --name Intermediate --usage delegate --out mid.json
```

### 2. SBOM verification (`sbom.py`)
The signed manifest can commit to an SBOM (`sign --sbom sbom.json` stores its SHA-256 as `sbom_sha256`). `verify --sbom` then checks that the SBOM is the committed one, describes **this** package (name, version, hash), and lists components; with `--advisories` it flags **vulnerable** components (`affected_below` / `affected_versions`) and **outdated** ones (`minimum_versions`). `--fail-on high|critical|medium|low|none` sets the blocking policy; `sbom-show` prints the dependency list. CycloneDX JSON and SPDX JSON are supported.
```bash
python relverify.py sbom-create --name app --version 1.0.0 --pkg app.zip --component openssl=1.0.2 --out sbom.json
python relverify.py sign --pkg app.zip --key acme.key --publisher Acme --version 1.0.0 --package-name app --sbom sbom.json --out app.json
python relverify.py verify --pkg app.zip --manifest app.json --trust-store trust.json --sbom sbom.json --advisories advisories.json
```

### 3. Transparency log (`translog.py`)
An append-only Merkle tree (RFC 6962/9162 hashing). `log-submit` records a signed release and issues a **receipt**: the log's signed tree head plus an inclusion proof. `verify --receipt` checks the log key (needs `key_usage: log`), the signature, and that this exact release is in the tree. The trust store remembers the last tree head it saw, and with `--log` the verifier checks a **consistency proof**, so a log that rewrites history or shows two different trees of the same size (split view) is detected. `--require-receipt` blocks unlogged releases. The head is only remembered if the whole verification succeeds. Merkle proofs are tested for every tree size up to 70.
```bash
python relverify.py trust-add --trust-store trust.json --pub log.pub --name "Log" --usage log
python relverify.py log-submit --log log.json --key log.key --manifest app.json --out receipt.json
python relverify.py verify --pkg app.zip --manifest app.json --trust-store trust.json --receipt receipt.json --log log.json
```

### 4. TUF-style metadata (`tufmeta.py`)
A simplified model of The Update Framework with four signed roles: **root** (trust anchor; rotates keys), **targets** (the packages and hashes that may be installed), **snapshot** (pins the targets file by hash) and **timestamp** (short-lived, pins the snapshot). Each role has keys and a signature threshold. It defends against freeze attacks (expiry), rollback (versions never decrease), mix-and-match (every file is hash-pinned by the one above), and key compromise (thresholds, plus root-signed key rotation that must be signed by both the old and new root keys). `verify --tuf-repo ... --tuf-state ...` also requires the package to be approved by the signed targets metadata.
```bash
python relverify.py tuf-init --repo repo --keys keys --threshold targets=2
python relverify.py tuf-add --repo repo --keys keys --pkg app.zip --name app --version 1.0.0
python relverify.py tuf-trust-root --root repo/root.json --state tuf-state.json   # compare the printed key IDs with the publisher!
python relverify.py tuf-verify --repo repo --state tuf-state.json --pkg app.zip --name app-1.0.0
python relverify.py tuf-rotate --repo repo --keys keys --role timestamp
```

### 5. Hardware keys / HSM (`signers.py`)
Every place that signs (releases, delegations, revocation lists, log tree heads) accepts a signer object, so the private key can stay inside a token: `--key "pkcs11:lib=/usr/lib/softhsm/libsofthsm2.so;token=MyToken;key=release;alg=rsa-pss"`. The PIN comes from `RELVERIFY_PIN` or a prompt, never the command line. Needs `pip install PyKCS11` (see `requirements-optional.txt`).

### Honest limits of version 4
- **HSM:** the signer interface and everything using it are tested with an in-memory stand-in that never exposes its key. The PKCS#11 adapter itself was **not run against real hardware or SoftHSM** in the build environment; test it with SoftHSM2 before relying on it.
- **Transparency log:** a reference implementation over a local file. There is no network log server, witness/gossip protocol or monitor service, so split views are only detected by clients that saw both heads.
- **TUF:** simplified. Not implemented: delegated targets roles, consistent-snapshot filenames, multiple mirrors, and metadata fetched over a network (it reads a directory).
- **SBOM:** advisories are an offline file you supply, not a live vulnerability database. Version comparison uses the numeric prefix (`1.2.3-beta` is treated as `1.2.3`); a component with an unparseable version is flagged as possibly vulnerable.
- The GUI does not yet expose SBOM, receipt, TUF or key-usage options; use the command line for these.

## Version 4.1: adversarial hardening (no new features)
Focus: prove that what exists survives hostile inputs, a hostile filesystem, crashes and races.

**Threat model for the install folder.** The install folder is a security boundary. The tool assumes it is owned by the current user and not writable by others; it refuses to run otherwise. A local attacker who can already write to the trust store or `state.json` is still out of scope (documented limit).

| Area | What changed |
|---|---|
| **Symlinks and permissions** | Refuses an install folder that is a symlink, owned by another user, or group/world-writable. Refuses a destination that is a symlink or directory. Symlinks and directories are ignored when reading installed versions. The lock is created with `O_EXCL`, so a symlink planted at the lock path is never followed. The installed file is re-hashed after the rename; if it changed, it is removed. The install folder is created `0700`. |
| **Crash recovery (journal)** | Every install writes `.update.journal` before the rename and deletes it after `state.json` is saved. The next run (or `recover`) finishes an install that crashed after the rename, discards one that crashed before it, removes leftover temp files, and **blocks** on a corrupt or forged journal instead of guessing. |
| **Lock handling** | The lock now records pid, host, time and a random token. `lock-status` classifies it as held / stale / other-host / unreadable. A lock is **stale only if** it names a process on this machine that is provably not running. Age alone never counts. `lock-break` removes only stale locks unless `--force`. A process only deletes a lock that still carries its own token. |
| **Audit policy, now defined** | A decision is only final once its audit record is durably written (write plus fsync). With `--audit-required`, any failure (missing folder, read-only log, full disk, fsync error, **corrupted log tail**) makes the result BLOCKED even though the security checks passed. Without it, a warning is printed. After an install the result is also chained into the log (`installed` or `install-failed`); that record is best effort because the state has already changed and cannot be undone. |
| **Parser hardening from fuzzing** | The fuzzers found real bugs: malformed JSON types could raise uncaught exceptions in certificate chains (unhashable key IDs), receipts, log files, SBOM/advisory files, the TUF root, and audit logs. None could cause an accept (they failed by crashing), but a verifier should return BLOCKED, not a traceback. All are fixed, and only `Block` or a clean error can now escape each parser. |

**The adversarial pack** (`tests/test_adversarial.py`, 50 tests, deterministic seeds, temporary folders only):
- *Filesystem:* symlinked install folder, destination, lock and version entries; unsafe permissions; hostile package names; swap after rename; package changed after verification.
- *Crash recovery:* simulated power loss (a `BaseException` no handler can swallow) before the rename, after the rename, and during the state write; corrupt or forged journals; journal that disagrees with the file; missing installed file.
- *Locks:* owner metadata, all four lock states, "old is not stale", break policy, hijacked lock, cleanup after every failure type, and four parallel updates that must serialise into a consistent result.
- *Audit:* disk-full and fsync failure, missing and read-only log, corrupted tail, tamper detection at every position.
- *Fuzzing (about 8,000 mutations):* every field of the release envelope, certificates, trust store, revocation list, transparency receipt and log file, SBOM and advisory files (CycloneDX and SPDX), all four TUF metadata files and the trusted root, `state.json` and the audit log, using type-swapping (null, numbers, huge values, lists, objects), deletions and byte-level mutation. Rules: nothing may raise, and nothing may be accepted unless its security-relevant content equals the original.

New commands: `recover`, `lock-status`, `lock-break [--force]`.

**Limits of this round.** PID-based stale detection can be fooled by PID reuse (hence no automatic lock removal). The Windows branch of the PID check and the permission checks are not exercised on Windows here. Deleting `key_usage` from a trust record falls back to the old default rights, which only matters to an attacker who can already edit the trust store. The journal and state are local files, so they are trusted as much as the trust store is.

## Limitations (worth stating in your report)
- The trust store and `state.json` are plain files; protect them with OS permissions or sign them.
- Revocation lists are files you must fetch yourself; there is no online CRL/OCSP service. (A local flag is still available.)
- Private keys are unencrypted unless `keygen --passphrase` is used; use an HSM in production.
- Rollback memory comes from `state.json` plus the installed files; an attacker who deletes both (or reinstalls the OS) resets it. A server-signed monotonic counter or TUF-style snapshot metadata would close that gap.
- Key validity is checked against the local clock.
- The trust store file is still protected only by OS permissions; a signed or hardware-backed store would be stronger.
- The audit log detects edits and removals inside the log, but deleting records from the END is only detectable if you saved the head hash printed by `audit-verify`.
- A lock left behind by a crash is detected (`lock-status`) and removed safely with `lock-break`; it is never removed automatically.
- The GUI could not be run in the build environment (no Tkinter), so it is compiled and reviewed but not executed; please test it on your machine.

