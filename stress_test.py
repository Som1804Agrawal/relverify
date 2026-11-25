#!/usr/bin/env python3
"""Stress test: N random trials per attack type. Run: python stress_test.py [N]"""
import base64, json, os, random, shutil, sys, tempfile, time
from collections import Counter
from core import *

N = int(sys.argv[1]) if len(sys.argv) > 1 else 1000
rng = random.Random(42)  # fixed seed so results are reproducible
W = tempfile.mkdtemp(prefix="relverify-stress-")
P = lambda n: os.path.join(W, n)

key = generate_key()
TS = P("trust.json"); TrustStore(TS).add("Acme", key.public_key())

def fresh():
    """a new random package + validly signed manifest (as a dict)"""
    open(P("pkg"), "wb").write(rng.randbytes(rng.randint(1000, 50000)))
    return create_release(P("pkg"), key, "Acme", "1.0.0")

def check(env=None):
    if env is not None:
        json.dump(env, open(P("man.json"), "w"))
    return verify_release(P("pkg"), P("man.json"), TS)

def a_clean(env):
    return check(env)

def a_bitflip(env):
    b = bytearray(open(P("pkg"), "rb").read()); b[rng.randrange(len(b))] ^= 1 << rng.randrange(8)
    open(P("pkg"), "wb").write(b); return check(env)

def a_truncate(env):
    b = open(P("pkg"), "rb").read(); open(P("pkg"), "wb").write(b[:rng.randrange(len(b))]); return check(env)

def a_append(env):
    open(P("pkg"), "ab").write(rng.randbytes(rng.randint(1, 100))); return check(env)

def a_manifest_edit(env):
    f = rng.choice(list(env["manifest"])); v = env["manifest"][f]
    i = rng.randrange(len(v)); c = rng.choice("0123456789abcdef")
    env["manifest"][f] = v[:i] + (c if c != v[i] else "z") + v[i + 1:]; return check(env)

def a_sig_flip(env):
    s = bytearray(base64.b64decode(env["signature"])); s[rng.randrange(len(s))] ^= 1 << rng.randrange(8)
    env["signature"] = base64.b64encode(bytes(s)).decode(); return check(env)

def a_fix_hash(env):  # attacker tampers package AND rewrites hash in manifest
    open(P("pkg"), "ab").write(b"MALWARE")
    env["manifest"]["sha256"] = sha256_file(P("pkg")); return check(env)

def a_unknown_key(env):  # attacker signs a tampered package with their own key
    open(P("pkg"), "ab").write(b"MALWARE")
    return check(create_release(P("pkg"), generate_key(), "Acme", "1.0.0"))

def a_swap(env):  # valid manifest of package A used with a different package B
    open(P("pkg"), "wb").write(rng.randbytes(2000)); return check(env)

def delegated():  # release signed by a NEW key that the trust store has never seen, via a certificate
    leaf = generate_key(); cert = create_delegation(key, leaf.public_key(), "Release key")
    open(P("pkg"), "wb").write(rng.randbytes(rng.randint(1000, 50000)))
    return create_release(P("pkg"), leaf, "Acme", "1.0.0", chain=[cert])

def a_chain_ok(env):
    return check(delegated())

def a_cert_edit(env):  # attacker edits one field of the delegation certificate
    env = delegated(); d = env["chain"][0]["delegation"]
    f = rng.choice([k for k, x in d.items() if isinstance(x, str) and k != "subject_public_key"]); v = d[f]
    i = rng.randrange(len(v)); c = rng.choice("0123456789abcdef")
    d[f] = v[:i] + (c if c != v[i] else "z") + v[i + 1:]; return check(env)

TESTS = [("Delegated release via valid chain (should be ACCEPTED)", a_chain_ok, True),
         ("Random edit to a delegation certificate", a_cert_edit, False),
         ("Clean release (should be ACCEPTED)", a_clean, True),
         ("Random single-bit flip in package", a_bitflip, False),
         ("Truncated package", a_truncate, False),
         ("Extra bytes appended to package", a_append, False),
         ("Random edit to a manifest field", a_manifest_edit, False),
         ("Random bit flip in signature", a_sig_flip, False),
         ("Package tampered + hash rewritten", a_fix_hash, False),
         ("Tampered package signed by attacker key", a_unknown_key, False),
         ("Valid manifest with a different package", a_swap, False)]

t0 = time.time(); rows = []; wrong_total = 0; accepted = 0
for name, fn, should_pass in TESTS:
    correct, reasons, spent = 0, Counter(), 0.0
    for _ in range(N):
        env = fresh(); s0 = time.perf_counter()
        r = fn(env); spent += time.perf_counter() - s0
        accepted += r.ok
        if r.ok == should_pass:
            correct += 1
        if not r.ok:
            reasons[r.reason.split(" (")[0].split(":")[0]] += 1
    wrong_total += N - correct
    rows.append((name, N, correct, N - correct, reasons.most_common(1)[0][0] if reasons else "-", spent / N * 1000))

lines = ["| Test | Trials | Correct | Wrong | Avg ms | Main block reason |", "|---|---|---|---|---|---|"]
lines += [f"| {n} | {t} | {c} | {w} | {ms:.2f} | {why} |" for n, t, c, w, why, ms in rows]
total = N * len(TESTS)
lines.append(f"| **Total** | **{total}** | **{total - wrong_total}** | **{wrong_total}** | **{sum(r[5] for r in rows) / len(rows):.2f}** | |")
out = "\n".join(lines)
print(out)
blocked = total - accepted
def bench(alg, size, runs):
    k = generate_key(alg); tmp = tempfile.mkdtemp(); st = TrustStore(os.path.join(tmp, "t.json")); st.add("B", k.public_key())
    p = os.path.join(tmp, "p"); open(p, "wb").write(os.urandom(size))
    json.dump(create_release(p, k, "B", "1.0.0"), open(os.path.join(tmp, "m.json"), "w"))
    s0 = time.perf_counter()
    for _ in range(runs):
        assert verify_release(p, os.path.join(tmp, "m.json"), st.path).ok
    shutil.rmtree(tmp); return (time.perf_counter() - s0) / runs * 1000

bench_lines = ["", "| Verification speed (avg ms per release) | 10 KB file | 20 MB file |", "|---|---|---|"]
for alg in ("ed25519", "rsa-pss"):
    bench_lines.append(f"| {alg} | {bench(alg, 10_000, 100):.2f} | {bench(alg, 20_000_000, 5):.1f} |")
out += "\n" + "\n".join(bench_lines)
print("\n" + "\n".join(bench_lines))
print(f"\nAccepted {accepted}/{total} ({100 * accepted / total:.1f}%), blocked {total - accepted}/{total} ({100 * (total - accepted) / total:.1f}%)")
print(f"Correct decisions: {total - wrong_total}/{total} = {100 * (total - wrong_total) / total:.2f}%   ({time.time() - t0:.1f}s)")
os.makedirs(os.path.join(os.path.dirname(os.path.abspath(__file__)), "docs"), exist_ok=True)
open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "docs", "stress_results.md"), "w").write(out + "\n")
shutil.rmtree(W, ignore_errors=True)
sys.exit(1 if wrong_total else 0)
