#!/usr/bin/env python3
"""Software Release Verification Tool. Exit code 0 = safe to install, 1 = blocked, 2 = usage/input error."""
import argparse, getpass, json, os, sys
from core import *
from updater import UpdateClient, break_lock, lock_status
import sbom, translog, tufmeta

def die(msg):
    print(msg, file=sys.stderr); sys.exit(2)

def read(path):
    with open(path) as f:
        return f.read()

def write(path, text):
    with open(path, "w") as f:
        f.write(text)

def ask_passphrase(prompt, confirm=False):
    env = os.environ.get("RELVERIFY_PASSPHRASE")  # convenient for tests; prefer the prompt in real use
    if env is not None:
        return env
    p = getpass.getpass(prompt)
    if confirm and getpass.getpass("Repeat passphrase: ") != p:
        die("passphrases do not match")
    return p

def load_signing_key(path):
    if path.startswith("pkcs11:"):  # key lives in an HSM / token and never leaves it
        import signers
        try:
            return signers.from_spec(path)
        except (RuntimeError, ValueError) as e:
            die(f"cannot use hardware key: {e}")
    pem = read(path)
    try:
        return load_private(pem, ask_passphrase("Key passphrase: ") if is_encrypted(pem) else None)
    except (ValueError, TypeError):
        die("could not load private key (wrong passphrase?)")

def show(res, verbose=True, as_json=False, pkg="", report=None):
    if report:
        write(report, format_report(res, pkg))
    if as_json:
        print(json.dumps({"ok": res.ok, "reason": res.reason or "ok", "manifest": res.manifest,
                          "steps": [list(s) for s in res.steps]}, indent=2))
    else:
        if verbose:
            for name, detail in res.steps:
                print(f"  [{'x' if name == 'BLOCKED' else 'ok'}] {name}" + (f": {detail}" if detail != "ok" else ""))
        print("VERIFIED: safe to install" if res.ok else f"BLOCKED: {res.reason}")
    return 0 if res.ok else 1

def main(argv=None):
    p = argparse.ArgumentParser(prog="relverify")
    p.add_argument("--debug", action="store_true", help="show full error details (before the command name)")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("keygen", help="create a key pair")
    s.add_argument("--alg", default="ed25519", choices=["ed25519", "rsa-pss"])
    s.add_argument("--out", required=True, help="prefix; writes PREFIX.key and PREFIX.pub")
    s.add_argument("--passphrase", action="store_true", help="encrypt the private key with a passphrase (recommended)")

    s = sub.add_parser("sign", help="sign a package, writing a manifest")
    s.add_argument("--pkg", required=True); s.add_argument("--key", required=True)
    s.add_argument("--publisher", required=True); s.add_argument("--version", required=True)
    s.add_argument("--out", required=True); s.add_argument("--days", type=int, default=90)
    s.add_argument("--package-name", help="name recorded in the manifest (default: file name)")
    s.add_argument("--embed-pubkey", action="store_true")
    s.add_argument("--sbom", help="SBOM file whose hash the signed manifest will commit to")
    s.add_argument("--chain", nargs="*", default=[], help="delegation certificate file(s), leaf first")

    s = sub.add_parser("delegate", help="issue a delegation certificate for a release key")
    s.add_argument("--issuer-key", required=True); s.add_argument("--subject-pub", required=True)
    s.add_argument("--name", required=True); s.add_argument("--days", type=int, default=180)
    s.add_argument("--packages", nargs="*", default=[], help="restrict to these package names (wildcards allowed)")
    s.add_argument("--usage", nargs="*", default=["release"], choices=list(USAGES),
                   help="what the delegated key may do (default: release). Use 'delegate' for intermediate CAs")
    s.add_argument("--max-depth", type=int, help="how many further certificates may be chained below this one (0 = none)")
    s.add_argument("--out", required=True)

    s = sub.add_parser("trust-add", help="trust a publisher's public key")
    s.add_argument("--trust-store", required=True); s.add_argument("--pub", required=True)
    s.add_argument("--name", required=True); s.add_argument("--days", type=int, default=365)
    s.add_argument("--usage", nargs="*", default=None, choices=list(USAGES),
                   help="what this key may be used for (default: release delegate revocation)")

    s = sub.add_parser("trust-list", help="show the trust store")
    s.add_argument("--trust-store", required=True)

    s = sub.add_parser("trust-revoke", help="locally revoke a key")
    s.add_argument("--trust-store", required=True); s.add_argument("--key-id", required=True)

    s = sub.add_parser("revoke-list", help="create a signed revocation list")
    s.add_argument("--key", required=True, help="private key of a trusted revocation authority")
    s.add_argument("--revoke", nargs="*", default=[], help="key IDs (16 hex) or cert:SERIAL to revoke (none = empty list)")
    s.add_argument("--number", type=int, required=True, help="list number; must only ever increase")
    s.add_argument("--days", type=int, default=30); s.add_argument("--out", required=True)

    s = sub.add_parser("audit-verify", help="check that an audit log has not been altered")
    s.add_argument("--audit-log", required=True)

    for name, helptext in (("verify", "Class A verifier"), ("update", "Class C update client")):
        s = sub.add_parser(name, help=helptext)
        s.add_argument("--pkg", required=True); s.add_argument("--manifest", required=True)
        s.add_argument("--trust-store", required=True)
        s.add_argument("--revocation-list"); s.add_argument("--audit-log")
        s.add_argument("--audit-required", action="store_true", help="block if the audit record cannot be written")
        s.add_argument("--max-crl-age", type=int, help="block if the revocation list is older than this many days")
        s.add_argument("--report", help="write a text verification report to this file")
        s.add_argument("--sbom", help="verify this SBOM against the manifest's SBOM hash")
        s.add_argument("--advisories", help="offline advisory file (vulnerable / minimum versions) used with --sbom")
        s.add_argument("--fail-on", default="high", choices=sbom.SEVERITIES + ["none"], help="block at this SBOM finding severity")
        s.add_argument("--receipt", help="transparency log receipt for this release")
        s.add_argument("--log", help="the transparency log file (used to prove it is append-only)")
        s.add_argument("--require-receipt", action="store_true", help="block releases that have no transparency receipt")
        s.add_argument("--tuf-repo", help="directory with TUF-style metadata that must also approve this package")
        s.add_argument("--tuf-state", help="client state file created by tuf-trust-root")
        if name == "verify":
            s.add_argument("--tofu", action="store_true", help="prompt to trust an unknown embedded key")
            s.add_argument("-q", "--quiet", action="store_true"); s.add_argument("--json", action="store_true")
        else:
            s.add_argument("--state", required=True); s.add_argument("--install-dir", required=True)

    s = sub.add_parser("sbom-create", help="write a CycloneDX SBOM")
    s.add_argument("--name", required=True); s.add_argument("--version", required=True); s.add_argument("--pkg", required=True)
    s.add_argument("--component", action="append", default=[], metavar="NAME=VERSION"); s.add_argument("--out", required=True)
    s = sub.add_parser("sbom-show", help="list the components of an SBOM and scan them")
    s.add_argument("--sbom", required=True); s.add_argument("--advisories")

    s = sub.add_parser("log-submit", help="add a signed release to a transparency log and write a receipt")
    s.add_argument("--log", required=True); s.add_argument("--key", required=True, help="the log's signing key (file or pkcs11:...)")
    s.add_argument("--manifest", required=True); s.add_argument("--out", required=True)
    s = sub.add_parser("log-show", help="print the size and root hash of a log")
    s.add_argument("--log", required=True)

    s = sub.add_parser("tuf-init", help="create a TUF-style repository and role keys")
    s.add_argument("--repo", required=True); s.add_argument("--keys", required=True)
    s.add_argument("--threshold", action="append", default=[], metavar="ROLE=N", help="signatures needed for a role")
    s = sub.add_parser("tuf-add", help="publish a package in the targets metadata")
    s.add_argument("--repo", required=True); s.add_argument("--keys", required=True)
    s.add_argument("--pkg", required=True); s.add_argument("--name", required=True); s.add_argument("--version", required=True)
    s = sub.add_parser("tuf-refresh", help="re-sign the short-lived timestamp")
    s.add_argument("--repo", required=True); s.add_argument("--keys", required=True)
    s = sub.add_parser("tuf-rotate", help="replace a role's keys (root-signed)")
    s.add_argument("--repo", required=True); s.add_argument("--keys", required=True); s.add_argument("--role", required=True, choices=list(tufmeta.ROLES))
    s = sub.add_parser("tuf-trust-root", help="trust a root.json (compare the key IDs out-of-band!)")
    s.add_argument("--root", required=True); s.add_argument("--state", required=True)
    s = sub.add_parser("tuf-verify", help="update TUF metadata and check a package against it")
    s.add_argument("--repo", required=True); s.add_argument("--state", required=True)
    s.add_argument("--pkg", required=True); s.add_argument("--name", required=True, help="target name, e.g. app-1.0.0")

    s = sub.add_parser("recover", help="finish or discard an interrupted install")
    s.add_argument("--state", required=True); s.add_argument("--install-dir", required=True)
    s = sub.add_parser("lock-status", help="show who holds the update lock and whether it looks stale")
    s.add_argument("--install-dir", required=True)
    s = sub.add_parser("lock-break", help="remove the update lock (only if provably stale, unless --force)")
    s.add_argument("--install-dir", required=True); s.add_argument("--force", action="store_true")

    s = sub.add_parser("installed", help="check installed packages against their recorded hashes")
    s.add_argument("--state", required=True); s.add_argument("--install-dir", required=True)

    sub.add_parser("gui", help="Class B desktop verifier")
    a = p.parse_args(argv)
    try:
        return dispatch(a)
    except SystemExit:
        raise
    except Exception as e:  # keep normal output free of internal details; --debug shows everything
        if a.debug:
            raise
        die(f"error: {type(e).__name__}: {str(e)[:200]} (rerun with --debug before the command for details)")


def dispatch(a):

    if a.cmd == "keygen":
        k = generate_key(a.alg)
        pw = ask_passphrase("New passphrase: ", confirm=True) if a.passphrase else None
        write_private(a.out + ".key", private_pem(k, pw)); write(a.out + ".pub", public_pem(k.public_key()))
        print(f"key_id {key_id_of(k.public_key())}  fingerprint {fingerprint(k.public_key())}"
              + ("  (private key encrypted)" if pw else "  (WARNING: private key is not encrypted; use --passphrase)"))
        return 0
    if a.cmd == "sign":
        try:
            env = create_release(a.pkg, load_signing_key(a.key), a.publisher, a.version, package_name=a.package_name,
                                 days_valid=a.days, embed_pubkey=a.embed_pubkey,
                                 chain=[json.loads(read(c)) for c in a.chain], sbom_path=a.sbom)
            validate_manifest(env["manifest"])  # refuse to sign something the verifier would reject
        except (OSError, ValueError) as e:
            die(f"cannot sign: {e}")
        write(a.out, json.dumps(env, indent=2)); print("wrote", a.out); return 0
    if a.cmd == "delegate":
        cert = create_delegation(load_signing_key(a.issuer_key), load_public(read(a.subject_pub)), a.name,
                                 days_valid=a.days, packages=a.packages, max_depth=a.max_depth,
                                 key_usage=a.usage)
        write(a.out, json.dumps(cert, indent=2))
        print(f"wrote {a.out}: {cert['delegation']['issuer_key_id']} vouches for {cert['delegation']['subject_key_id']}"
              f" (certificate serial {cert['delegation']['serial']})"
              + (f" (packages: {', '.join(a.packages)})" if a.packages else "")); return 0
    if a.cmd == "trust-add":
        r = TrustStore(a.trust_store).add(a.name, load_public(read(a.pub)), days=a.days, usage=a.usage)
        print("trusted", r["key_id"], r["fingerprint"], "usage:", ",".join(r["key_usage"])); return 0
    if a.cmd == "trust-list":
        for r in TrustStore(a.trust_store).records.values():
            print(f"{r['key_id']}  {r['name']:<20} {r['alg']:<8} {r['not_before'][:10]}..{r['not_after'][:10]}  "
                  + ("REVOKED" if r["revoked"] else "active") + "  [" + ",".join(usage_of(r)) + "]")
        return 0
    if a.cmd == "trust-revoke":
        TrustStore(a.trust_store).revoke(a.key_id); print("revoked", a.key_id); return 0
    if a.cmd == "revoke-list":
        try:
            env = create_revocation_list(load_signing_key(a.key), a.revoke, a.number, a.days)
        except ValueError as e:
            die(f"cannot create list: {e}")
        write(a.out, json.dumps(env, indent=2)); print(f"wrote {a.out} (number {a.number}, revokes {len(a.revoke)} key(s))"); return 0
    if a.cmd == "audit-verify":
        ok, n, msg = verify_audit_log(a.audit_log)
        print(("AUDIT LOG OK: " if ok else "AUDIT LOG TAMPERED: ") + f"{n} record(s) checked, {msg}")
        return 0 if ok else 1
    if a.cmd == "verify":
        def ask(pub, kid, fp):
            print(f"Unknown publisher '{pub}'\n  key_id {kid}\n  fingerprint {fp}")
            return input("Trust this key? [y/N] ").strip().lower() == "y"
        findings = []
        res = verify_release(a.pkg, a.manifest, a.trust_store, tofu=ask if a.tofu else None, revocation_path=a.revocation_list,
                             audit_log=a.audit_log, revocation_max_age_days=a.max_crl_age,
                             audit_required=a.audit_required, extra_checks=build_checks(a, findings))
        if findings and not a.json:
            for f in findings:
                print(f"  ! {f['kind']}: {f['component']} {f['version']} ({f['severity']}, {f['id']}, fix: {f['fixed_in']})")
        return show(res, not a.quiet, a.json, a.pkg, a.report)
    if a.cmd == "update":
        client = UpdateClient(a.trust_store, a.state, a.install_dir, a.revocation_list, a.audit_log, a.audit_required,
                              extra_checks=build_checks(a, []))
        return show(client.apply(a.pkg, a.manifest), pkg=a.pkg, report=a.report)
    if a.cmd == "sbom-create":
        comps = []
        for c in a.component:
            n, _, v = c.partition("="); comps.append((n, v))
        write(a.out, json.dumps(sbom.create_cyclonedx(a.name, a.version, sha256_file(a.pkg), comps), indent=2))
        print(f"wrote {a.out} ({len(comps)} components)"); return 0
    if a.cmd == "sbom-show":
        try:
            sb = sbom.load_sbom(a.sbom)
        except (OSError, ValueError) as e:
            die(f"cannot read SBOM: {e}")
        print(f"{sb['format']}: {sb['main']['name']} {sb['main']['version']}, {len(sb['components'])} components")
        found = sbom.scan(sb["components"], sbom.load_advisories(a.advisories)) if a.advisories else []
        flagged = {(f["component"], f["version"]): f for f in found}
        for c in sb["components"]:
            f = flagged.get((c["name"], c["version"] or "unknown"))
            print(f"  {c['name']:<24} {c['version'] or '?':<12}" + (f"  <-- {f['kind']} {f['id']} ({f['severity']})" if f else ""))
        return 1 if any(f["kind"] == "vulnerable" for f in found) else 0
    if a.cmd == "log-submit":
        lg, signer = translog.Log(a.log), load_signing_key(a.key)
        env = json.loads(read(a.manifest))
        idx = lg.append(translog.entry_for(env["manifest"], env["signature"]))
        write(a.out, json.dumps(lg.receipt(idx, signer), indent=1))
        print(f"logged as entry #{idx}; log now has {lg.size()} entries; wrote receipt {a.out}"); return 0
    if a.cmd == "log-show":
        lg = translog.Log(a.log); print(f"entries: {lg.size()}  root: {lg.root().hex()}"); return 0
    if a.cmd.startswith("tuf-"):
        return tuf_command(a)
    if a.cmd == "recover":
        ok, msgs = UpdateClient("", a.state, a.install_dir).recover()
        for m in msgs or ["nothing to recover"]:
            print(m)
        return 0 if ok else 1
    if a.cmd == "lock-status":
        st = lock_status(a.install_dir)
        print("no lock" if st is None else f"lock {st['state']}: pid {st['pid']} on {st['host']} since {st['time']}")
        return 0
    if a.cmd == "lock-break":
        ok, msg = break_lock(a.install_dir, a.force); print(msg); return 0 if ok or "no lock" in msg else 1
    if a.cmd == "installed":
        rows = UpdateClient("", a.state, a.install_dir).status()
        for row in rows:
            print(f"{row['package']:<20} {row['version']:<12} {row['status']}")
        if not rows:
            print("nothing recorded as installed")
        return 0 if all(x["status"].startswith("ok") for x in rows) else 1
    if a.cmd == "gui":
        import gui; gui.run(); return 0

def build_checks(a, findings):
    """Turn the optional command-line features into plug-in checks for verify_release."""
    checks = []
    if getattr(a, "sbom", None):
        checks.append(sbom.make_check(a.sbom, a.advisories, a.fail_on, findings))
    if getattr(a, "receipt", None) or getattr(a, "require_receipt", False):
        if not a.receipt:
            die("--require-receipt needs --receipt FILE")
        checks.append(translog.make_check(a.receipt, a.log))
    if getattr(a, "tuf_repo", None):
        if not a.tuf_state:
            die("--tuf-repo needs --tuf-state (create it with tuf-trust-root)")
        checks.append(tufmeta.make_check(tufmeta.Client(a.tuf_state), a.tuf_repo))
    return checks


def tuf_command(a):
    if a.cmd == "tuf-init":
        th = {}
        for t in a.threshold:
            role, _, n = t.partition("=")
            if role not in tufmeta.ROLES or not n.isdigit() or int(n) < 1:
                die("--threshold must look like targets=2")
            th[role] = int(n)
        tufmeta.Repo(a.repo, a.keys).init(th)
        print(f"created TUF-style repository in {a.repo}; keys in {a.keys} (keep these private)"); return 0
    if a.cmd == "tuf-add":
        tufmeta.Repo(a.repo, a.keys).add_target(a.pkg, a.name, a.version); print(f"published {a.name}-{a.version}"); return 0
    if a.cmd == "tuf-refresh":
        tufmeta.Repo(a.repo, a.keys).refresh_timestamp(); print("timestamp re-signed"); return 0
    if a.cmd == "tuf-rotate":
        tufmeta.Repo(a.repo, a.keys).rotate_key(a.role); print(f"{a.role} keys rotated (new root version published)"); return 0
    if a.cmd == "tuf-trust-root":
        try:
            ids = tufmeta.Client.trust_root(a.state, a.root)
        except (Block, OSError, ValueError, KeyError) as e:
            die(f"cannot trust this root: {e}")
        print("trusted root. Compare these key IDs with the publisher:")
        for role, keys in ids.items():
            print(f"  {role:<10} {', '.join(keys)}")
        return 0
    if a.cmd == "tuf-verify":
        client = tufmeta.Client(a.state)
        try:
            targets = client.refresh(a.repo)
            tufmeta.verify_target(targets, a.name, a.pkg)
        except Block as b:
            print(f"BLOCKED: {b}"); return 1
        client.save(); v = client.state["versions"]
        print(f"VERIFIED by TUF metadata (root v{client.state['root']['signed']['version']}, targets v{v['targets']}): {a.name}")
        return 0


if __name__ == "__main__":
    sys.exit(main())