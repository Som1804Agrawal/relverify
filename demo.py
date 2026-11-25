#!/usr/bin/env python3
"""Tamper demo for classes A, B and C. Run: python3 demo.py"""
import json, os, subprocess, sys, tempfile
from datetime import timedelta
from core import *
from updater import UpdateClient

HERE = os.path.dirname(os.path.abspath(__file__))
W = tempfile.mkdtemp(prefix="relverify-demo-")
P = lambda n: os.path.join(W, n)
def title(t): print(f"\n=== {t} ===")
def cli(*args):
    r = subprocess.run([sys.executable, os.path.join(HERE, "relverify.py"), *args], capture_output=True, text=True)
    print(r.stdout.rstrip()); print(f"exit code: {r.returncode}"); return r.returncode
def flip_byte(path, offset=100):
    b = bytearray(open(path, "rb").read()); b[offset] ^= 0x01; open(path, "wb").write(b)
def make_pkg(name, size=200_000):
    open(P(name), "wb").write(os.urandom(size)); return P(name)

# publisher + trust store
key = generate_key("ed25519"); rsa_key = generate_key("rsa-pss")
ts = TrustStore(P("trust.json"))
ts.add("Acme Software", key.public_key()); ts.add("Acme RSA", rsa_key.public_key())
def release(pkg, k=key, version="1.0.0", out=None, **kw):
    out = out or P(os.path.basename(pkg) + ".json")
    json.dump(create_release(pkg, k, "Acme Software", version, **kw), open(out, "w"), indent=2); return out

# ---------------- Class A: CLI ----------------
title("A1. clean package (Ed25519) -> must PASS (exit 0)")
pkg = make_pkg("app.tar.gz"); man = release(pkg)
assert cli("verify", "--pkg", pkg, "--manifest", man, "--trust-store", P("trust.json")) == 0

title("A2. clean package signed with RSA-PSS -> must PASS")
pkg_r = make_pkg("rsa-app.tar.gz"); man_r = release(pkg_r, rsa_key)
assert cli("verify", "--pkg", pkg_r, "--manifest", man_r, "--trust-store", P("trust.json"), "-q") == 0

title("A3. flip ONE byte in the package -> hash mismatch, BLOCKED")
tampered = P("tampered.tar.gz"); open(tampered, "wb").write(open(pkg, "rb").read()); flip_byte(tampered)
assert cli("verify", "--pkg", tampered, "--manifest", man, "--trust-store", P("trust.json")) != 0

title("A4. edit the manifest (attacker fixes the hash to match tampered pkg) -> bad signature, BLOCKED")
env = json.load(open(man)); env["manifest"]["sha256"] = sha256_file(tampered)
forged = P("forged.json"); json.dump(env, open(forged, "w"))
assert cli("verify", "--pkg", tampered, "--manifest", forged, "--trust-store", P("trust.json")) != 0

title("A5. attacker signs with their OWN key (not in trust store) -> BLOCKED")
evil = generate_key(); pkg_e = make_pkg("evil.tar.gz"); man_e = release(pkg_e, evil)
assert cli("verify", "--pkg", pkg_e, "--manifest", man_e, "--trust-store", P("trust.json"), "-q") != 0

# ---------------- Class B: trust records + TOFU ----------------
title("B1. unknown publisher, user ACCEPTS first-use prompt -> PASS, record saved")
newpub = generate_key(); pkg_n = make_pkg("new.tar.gz")
man_n = release(pkg_n, newpub, embed_pubkey=True)
seen = []
res = verify_release(pkg_n, man_n, P("trust.json"), tofu=lambda n, k, f: (seen.append((n, k, f)), True)[1])
print("prompt shown:", seen[0][0], seen[0][1], seen[0][2][:16] + "...")
print("result:", "PASS" if res.ok else "BLOCKED " + res.reason); assert res.ok
assert TrustStore(P("trust.json")).get(key_id_of(newpub.public_key()))

title("B2. unknown publisher, user DECLINES -> BLOCKED")
pkg_d = make_pkg("decline.tar.gz"); man_d = release(pkg_d, generate_key(), embed_pubkey=True)
res = verify_release(pkg_d, man_d, P("trust.json"), tofu=lambda *a: False)
print("result:", res.reason); assert not res.ok

title("B3. publisher key REVOKED in trust store -> BLOCKED")
TrustStore(P("trust.json")).revoke(key_id_of(rsa_key.public_key()))
res = verify_release(pkg_r, man_r, P("trust.json")); print("result:", res.reason); assert not res.ok

# ---------------- Class C: update client ----------------
title("C1. install v1.0.0, then v2.0.0 (valid upgrades)")
uc = UpdateClient(P("trust.json"), P("state.json"), P("installed"))
for v in ("1.0.0", "2.0.0"):
    p = make_pkg(f"tool-{v}.bin"); r = uc.apply(p, release(p, version=v, package_name="tool"))
    print(f"  v{v}:", "INSTALLED" if r.ok else "BLOCKED " + r.reason); assert r.ok

title("C2. ROLLBACK: validly signed OLDER version 1.5.0 -> BLOCKED")
p = make_pkg("tool-1.5.0.bin"); r = uc.apply(p, release(p, version="1.5.0", package_name="tool"))
print("  result:", r.reason); assert not r.ok
r = uc.apply(p, release(p, version="2.0.0", package_name="tool"))
print("  same version replay:", r.reason); assert not r.ok

title("C3. EXPIRED SIGNING KEY -> BLOCKED")
old = generate_key(); TrustStore(P("trust.json")).add(
    "Acme (old key)", old.public_key(), not_before=now_utc() - timedelta(days=730), not_after=now_utc() - timedelta(days=1))
p = make_pkg("tool-3.0.0.bin"); r = uc.apply(p, release(p, old, version="3.0.0", package_name="tool"))
print("  result:", r.reason); assert not r.ok

title("C4. EXPIRED MANIFEST -> BLOCKED")
p = make_pkg("tool-4.0.0.bin"); past = now_utc() - timedelta(days=10)
r = uc.apply(p, release(p, version="4.0.0", package_name="tool", timestamp=past, expiry=past + timedelta(days=1)))
print("  result:", r.reason); assert not r.ok

title("C5. ALTERED MANIFEST (bump version to 9.9.9 to dodge rollback check) -> BLOCKED")
p = make_pkg("tool-2.5.0.bin"); m = release(p, version="2.5.0", package_name="tool")
env = json.load(open(m)); env["manifest"]["version"] = "9.9.9"; json.dump(env, open(m, "w"))
r = uc.apply(p, m); print("  result:", r.reason); assert not r.ok
print("\ninstalled state:", json.load(open(P("state.json"))))
print("\nAll demo assertions passed. Workdir:", W)
