#!/usr/bin/env python3
"""Guided class demo. Just run:  python class_demo.py   and press Enter at each step."""
import json, os, shutil, subprocess, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
AUTO = "--auto" in sys.argv
# work in the system temp folder (not OneDrive, which can lock files)
W = tempfile.mkdtemp(prefix="relverify-class-demo-")
os.chdir(W)
PY = os.path.basename(sys.executable) if os.name == "nt" else "python3"

def pause(msg=""):
    if not AUTO:
        input(f"\n{msg}  [press Enter to continue] ")

def run(*args, show=None):
    print(f"\n> {show or 'python relverify.py ' + ' '.join(args)}")
    r = subprocess.run([sys.executable, os.path.join(HERE, "relverify.py"), *args], capture_output=True, text=True)
    print(r.stdout.rstrip() + r.stderr.rstrip())
    print(f"(exit code: {r.returncode})")
    return r.returncode

def say(text):
    print(f"\n  SAY: {text}")

def make_pkg():
    open("myfile.zip", "wb").write(b"pretend this is real software " * 2000)

def sign(version="1.0.0", out="myfile.json"):
    run("sign", "--pkg", "myfile.zip", "--key", "acme.key", "--publisher", "Acme", "--version", version, "--out", out)

V = ["--pkg", "myfile.zip", "--manifest", "myfile.json", "--trust-store", "trust.json"]

print("=" * 60 + "\n RELEASE VERIFICATION TOOL - GUIDED DEMO\n" + "=" * 60)
print("Each step shows the command it runs and what to say. Just press Enter.")
pause("Ready?")

print("\n--- SETUP: publisher creates keys, you trust them, publisher signs a package ---")
make_pkg()
run("keygen", "--out", "acme")
run("trust-add", "--trust-store", "trust.json", "--pub", "acme.pub", "--name", "Acme")
sign()
say("The publisher signed the package. We trust the publisher's public key.")
pause("Setup done.")

print("\n--- STEP 1: clean package should be accepted ---")
assert run("verify", *V) == 0
say("Everything checks out, so exit code 0 means safe to install.")
pause("Next: tamper with the package.")

print("\n--- STEP 2: flip ONE byte in the package ---")
b = bytearray(open("myfile.zip", "rb").read()); b[10] ^= 1; open("myfile.zip", "wb").write(b)
print("(changed one bit of myfile.zip)")
assert run("verify", *V) != 0
say("One bit changed and the hash no longer matches. Installation is blocked, exit code 1.")
pause("Next: tamper with the manifest.")

print("\n--- STEP 3: edit the manifest (fresh package first) ---")
make_pkg(); sign()
t = open("myfile.json").read().replace('"version": "1.0.0"', '"version": "9.9.9"')
open("myfile.json", "w").write(t)
print('(changed "version" in myfile.json from 1.0.0 to 9.9.9)')
assert run("verify", *V) != 0
say("The attacker can edit the manifest, but cannot re-sign it. The signature check fails.")
pause("Next: the update client (Class C).")

print("\n--- STEP 4: update client rejects rollback ---")
make_pkg()
U = lambda m: ["update", "--pkg", "myfile.zip", "--manifest", m, "--trust-store", "trust.json",
               "--state", "state.json", "--install-dir", "installed"]
for v in ("1.0.0", "2.0.0", "1.5.0"):
    sign(v, f"m{v}.json")
    print(f"\n  >>> offering version {v}")
    run(*U(f"m{v}.json"))
print("\n  >>> attacker deletes state.json to wipe the rollback memory, then offers 1.5.0 again")
os.remove("state.json")
run(*U("m1.5.0.json"))
say("Versions 1.0.0 and 2.0.0 installed. 1.5.0 is validly signed but older, so rollback is rejected, even after the state file is deleted (the installed files remember too).")
pause("Next: revoke the publisher's key.")

print("\n--- STEP 5: signed revocation list (revoking a key remotely) ---")
make_pkg(); sign()
acme_id = list(json.load(open("trust.json"))["publishers"])[0]["key_id"]
run("keygen", "--out", "authority")
run("trust-add", "--trust-store", "trust.json", "--pub", "authority.pub", "--name", "Revocation Authority")
VL = lambda f: [*V, "--revocation-list", f, "--audit-log", "audit.log"]
run("revoke-list", "--key", "authority.key", "--number", "1", "--out", "crl1.json")
print("\n  >>> empty list: nothing revoked yet")
assert run("verify", *VL("crl1.json")) == 0
run("revoke-list", "--key", "authority.key", "--number", "2", "--revoke", acme_id, "--out", "crl2.json")
print("\n  >>> new signed list revokes Acme's key")
assert run("verify", *VL("crl2.json")) != 0
print("\n  >>> attacker replays the OLD list to un-revoke the key")
assert run("verify", *VL("crl1.json")) != 0
say("A trusted authority signed the revocation list, so devices learn about revoked keys. Replaying the old list is rejected too.")
pause("Next: local revocation.")

print("\n--- STEP 6: key delegation (certificate chain) ---")
make_pkg()
run("keygen", "--out", "release")
run("delegate", "--issuer-key", "acme.key", "--subject-pub", "release.pub", "--name", "Release key 2026", "--out", "cert.json")
run("sign", "--pkg", "myfile.zip", "--key", "release.key", "--publisher", "Acme", "--version", "3.0.0",
    "--out", "myfile.json", "--chain", "cert.json")
print("\n  >>> release key is NOT in the trust store, but Acme vouched for it")
assert run("verify", *V) == 0
t = open("cert.json").read().replace("Release key 2026", "Evil key"); open("cert_forged.json", "w").write(t)
run("sign", "--pkg", "myfile.zip", "--key", "release.key", "--publisher", "Acme", "--version", "3.0.0",
    "--out", "forged.json", "--chain", "cert_forged.json")
print("\n  >>> attacker edits the certificate")
assert run("verify", "--pkg", "myfile.zip", "--manifest", "forged.json", "--trust-store", "trust.json") != 0
run("delegate", "--issuer-key", "acme.key", "--subject-pub", "release.pub", "--name", "Old key", "--days", "-1", "--out", "cert_old.json")
run("sign", "--pkg", "myfile.zip", "--key", "release.key", "--publisher", "Acme", "--version", "3.0.0",
    "--out", "old.json", "--chain", "cert_old.json")
print("\n  >>> certificate that has already expired")
assert run("verify", "--pkg", "myfile.zip", "--manifest", "old.json", "--trust-store", "trust.json") != 0
say("Only Acme's root key is trusted. Short-lived release keys are vouched for by certificates, so keys can be rotated without touching the trust store.")
pause("Next: local revocation.")

print("\n--- STEP 7: path traversal attempt (hostile package name) ---")
sys.path.insert(0, HERE)
import base64, core
key = core.load_private(open("acme.key").read())
make_pkg()
m = core.create_release("myfile.zip", key, "Acme", "4.0.0")["manifest"]
m["package"] = "../../evil"  # a validly SIGNED manifest that tries to install outside the install folder
json.dump({"manifest": m, "alg": "ed25519", "signature": base64.b64encode(core.sign_bytes(key, core.canonical(m))).decode()},
          open("evil.json", "w"))
assert run("verify", "--pkg", "myfile.zip", "--manifest", "evil.json", "--trust-store", "trust.json") != 0
say("Even a correctly signed manifest is rejected if its package name could escape the install folder.")
pause("Next: the audit log.")

print("\n--- STEP 8: tamper-evident audit log ---")
assert run("audit-verify", "--audit-log", "audit.log") == 0
lines = open("audit.log").read().splitlines()
rec = json.loads(lines[1]); rec["allowed"] = not rec["allowed"]; lines[1] = json.dumps(rec)
open("audit.log", "w").write("\n".join(lines) + "\n")
print("\n  >>> someone edits one record in the log to hide a blocked install")
assert run("audit-verify", "--audit-log", "audit.log") != 0
say("Each log record contains the hash of the previous one, so editing or removing a record breaks the chain.")
pause("Next: local revocation.")

print("\n--- STEP 9: SBOM verification (what is inside the release?) ---")
make_pkg()
run("sbom-create", "--name", "app", "--version", "5.0.0", "--pkg", "myfile.zip", "--component", "openssl=1.0.2",
    "--component", "zlib=1.3.1", "--out", "sbom.json")
run("sign", "--pkg", "myfile.zip", "--key", "acme.key", "--publisher", "Acme", "--version", "5.0.0",
    "--package-name", "app", "--out", "myfile.json", "--sbom", "sbom.json")
json.dump({"vulnerabilities": [{"id": "CVE-DEMO-1", "component": "openssl", "severity": "high", "affected_below": "1.1.0",
                                 "fixed_in": "1.1.0"}]}, open("adv.json", "w"))
print("\n  >>> the signed manifest commits to the SBOM's hash; SBOM matches, no advisories")
assert run("verify", *V, "--sbom", "sbom.json") == 0
print("\n  >>> same release, checked against a vulnerability advisory list")
assert run("verify", *V, "--sbom", "sbom.json", "--advisories", "adv.json") != 0
sb = json.load(open("sbom.json")); sb["components"].append({"type": "library", "name": "backdoor", "version": "1"})
json.dump(sb, open("sbom.json", "w"))
print("\n  >>> someone adds a component to the SBOM after signing")
assert run("verify", *V, "--sbom", "sbom.json") != 0
say("The signature covers the SBOM's hash, so the SBOM cannot be swapped, and known-vulnerable libraries can be blocked by policy.")
pause("Next: the transparency log.")

print("\n--- STEP 10: transparency log (no secret releases) ---")
run("keygen", "--out", "logkey")
run("trust-add", "--trust-store", "trust.json", "--pub", "logkey.pub", "--name", "Transparency Log", "--usage", "log")
make_pkg(); sign()
run("log-submit", "--log", "log.json", "--key", "logkey.key", "--manifest", "myfile.json", "--out", "receipt.json")
print("\n  >>> release 1.0.0 was published in the public log")
assert run("verify", *V, "--receipt", "receipt.json", "--log", "log.json") == 0
sign("2.0.0", "secret.json")
print("\n  >>> a validly signed release 2.0.0 that was NEVER logged (e.g. shown only to one victim)")
assert run("verify", "--pkg", "myfile.zip", "--manifest", "secret.json", "--trust-store", "trust.json", "--receipt", "receipt.json") != 0
say("A stolen key cannot be used for a targeted attack in secret: every release must be provably in an append-only log.")
pause("Next: TUF-style metadata.")

print("\n--- STEP 11: TUF-style metadata (freeze, rollback, mix-and-match protection) ---")
make_pkg()
run("tuf-init", "--repo", "repo", "--keys", "keys", "--threshold", "targets=2")
run("tuf-add", "--repo", "repo", "--keys", "keys", "--pkg", "myfile.zip", "--name", "app", "--version", "1.0.0")
run("tuf-trust-root", "--root", "repo/root.json", "--state", "tuf-state.json")
TV = lambda n: ["tuf-verify", "--repo", "repo", "--state", "tuf-state.json", "--pkg", "myfile.zip", "--name", n]
assert run(*TV("app-1.0.0")) == 0
shutil.copytree("repo", "repo_old")
run("tuf-add", "--repo", "repo", "--keys", "keys", "--pkg", "myfile.zip", "--name", "app", "--version", "1.0.1")
assert run(*TV("app-1.0.1")) == 0
print("\n  >>> attacker restores the OLD (validly signed) repository to hide the new release")
shutil.rmtree("repo"); shutil.copytree("repo_old", "repo")
assert run(*TV("app-1.0.0")) != 0
say("Targets need 2 of 2 signatures, every file is pinned by hash from the one above, and version numbers can never go backwards.")
pause("Next: key usage restrictions.")

print("\n--- STEP 12: key usage restrictions ---")
run("keygen", "--out", "revonly")
run("trust-add", "--trust-store", "trust.json", "--pub", "revonly.pub", "--name", "Revocation-only key", "--usage", "revocation")
make_pkg()
run("sign", "--pkg", "myfile.zip", "--key", "revonly.key", "--publisher", "Acme", "--version", "1.0.0", "--out", "x.json")
print("\n  >>> a trusted key that is only allowed to sign revocation lists tries to sign a release")
assert run("verify", "--pkg", "myfile.zip", "--manifest", "x.json", "--trust-store", "trust.json") != 0
run("trust-list", "--trust-store", "trust.json")
say("Every key has a job (release, delegate, revocation, log). A key used for the wrong job is rejected, which limits the damage if one is stolen.")
pause("Next: local revocation.")

print("\n--- STEP 13: crash recovery (power cut during an install) ---")
from unittest import mock
sys.path.insert(0, HERE); import updater
class Crash(BaseException):
    pass
make_pkg(); sign("7.0.0", "crash.json")
real_write = updater.atomic_write
def crashy(path, text):
    if os.path.basename(path) == "state2.json":
        raise Crash()          # the machine dies right here
    return real_write(path, text)
try:
    with mock.patch("updater.atomic_write", side_effect=crashy):
        updater.UpdateClient("trust.json", "state2.json", "installed2").apply("myfile.zip", "crash.json")
except Crash:
    print("\n  >>> power cut: file renamed into place, but state.json was never written")
print("  files now:", sorted(os.listdir("installed2")))
run("recover", "--state", "state2.json", "--install-dir", "installed2")
run("installed", "--state", "state2.json", "--install-dir", "installed2")
say("A journal records every install before it happens, so after a crash the next run finishes it or discards it, and the install folder and state never disagree.")
pause("Next: local revocation.")

print("\n--- STEP 14: revoke the key locally ---")
make_pkg(); sign()
kid = list(json.load(open("trust.json"))["publishers"])[0]["key_id"]
run("trust-revoke", "--trust-store", "trust.json", "--key-id", kid)
assert run("verify", *V) != 0
say("Even a perfectly valid package is blocked once its signing key is revoked.")

print("\n" + "=" * 60 + "\n DONE. Every tampering attempt was blocked.\n" + "=" * 60)
