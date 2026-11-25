"""RelVerify adversarial test pack: hostile filesystems, crashes, locks, and parser fuzzing.
Run:  python -m unittest tests.test_adversarial -v      (or: python -W error::ResourceWarning -m unittest discover -s tests)
Everything runs in temporary folders and is deterministic (fixed random seeds)."""
import base64, contextlib, copy, io, json, os, random, shutil, socket, subprocess, sys, tempfile, threading, unittest
from datetime import timedelta
from unittest import mock
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from core import *
import updater, sbom, translog, tufmeta
from updater import UpdateClient

POSIX = os.name == "posix"
IS_ROOT = POSIX and os.geteuid() == 0

def rt(p):
    with open(p) as f: return f.read()
def wt(p, s):
    with open(p, "w") as f: f.write(s)
def rb(p):
    with open(p, "rb") as f: return f.read()
def wb(p, b):
    with open(p, "wb") as f: f.write(b)
def ab(p, b):
    with open(p, "ab") as f: f.write(b)
def rj(p):
    with open(p) as f: return json.load(f)
def wj(p, o):
    with open(p, "w") as f: json.dump(o, f)


class Crash(BaseException):
    """Simulated power loss / kill: not an Exception, so no handler in the code under test may swallow it."""


class Base(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(); self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)
        os.chmod(self.d, 0o700)
        self.p = lambda *n: os.path.join(self.d, *n)
        self.key = generate_key(); self.trust = self.p("trust.json"); TrustStore(self.trust).add("Acme", self.key.public_key())
        self.state, self.inst = self.p("state.json"), self.p("inst")

    def pkg(self, name="a.bin", data=None):
        wb(self.p(name), data or os.urandom(3000)); return self.p(name)

    def sign(self, pkg, version="1.0.0", key=None, **kw):
        out = pkg + f".{version}.json"; wj(out, create_release(pkg, key or self.key, "Acme", version, package_name="app", **kw)); return out

    def client(self, **kw):
        return UpdateClient(self.trust, self.state, self.inst, **kw)


# =====================================================================================
# 1. FILESYSTEM ATTACKS
# =====================================================================================
@unittest.skipUnless(POSIX, "symlinks and permission bits are tested on POSIX")
class FilesystemAttacks(Base):
    def test_install_dir_that_is_a_symlink_is_refused(self):
        victim = self.p("victim"); os.mkdir(victim); os.symlink(victim, self.inst)
        pkg = self.pkg(); r = self.client().apply(pkg, self.sign(pkg))
        self.assertIn("symbolic link", r.reason); self.assertEqual(os.listdir(victim), [])

    def test_group_or_world_writable_install_dir_is_refused(self):
        c = self.client(); os.chmod(self.inst, 0o777); pkg = self.pkg()
        self.assertIn("writable by other users", c.apply(pkg, self.sign(pkg)).reason)
        os.chmod(self.inst, 0o770); self.assertIn("writable by other users", c.apply(pkg, self.sign(pkg)).reason)
        os.chmod(self.inst, 0o700); self.assertTrue(c.apply(pkg, self.sign(pkg)).ok)

    def test_install_dir_is_created_private(self):
        self.client(); self.assertEqual(os.stat(self.inst).st_mode & 0o077, 0)

    def test_symlink_planted_at_destination_is_not_followed(self):
        victim = self.p("victim.txt"); wt(victim, "precious"); os.makedirs(self.inst, exist_ok=True); os.chmod(self.inst, 0o700)
        os.symlink(victim, os.path.join(self.inst, "app-1.0.0"))
        pkg = self.pkg(); r = self.client().apply(pkg, self.sign(pkg))
        self.assertIn("symbolic link", r.reason); self.assertEqual(rt(victim), "precious")

    def test_planted_symlink_does_not_count_as_an_installed_version(self):
        os.makedirs(self.inst, exist_ok=True); os.chmod(self.inst, 0o700); os.symlink("/nonexistent", os.path.join(self.inst, "app-99.0.0"))
        self.assertIsNone(self.client().installed_version("app"))

    def test_directory_at_destination_is_refused(self):
        os.makedirs(os.path.join(self.inst, "app-1.0.0")); os.chmod(self.inst, 0o700)
        pkg = self.pkg(); self.assertFalse(self.client().apply(pkg, self.sign(pkg)).ok)

    def test_symlink_planted_at_lock_path_is_not_followed(self):
        victim = self.p("victim.txt"); wt(victim, "precious"); self.client(); os.symlink(victim, os.path.join(self.inst, ".update.lock"))
        pkg = self.pkg(); r = self.client().apply(pkg, self.sign(pkg))
        self.assertIn("holds the lock", r.reason); self.assertEqual(rt(victim), "precious")

    def test_file_swapped_right_after_the_rename_is_detected_and_removed(self):
        real_replace = os.replace
        def replace_then_tamper(a, b):
            real_replace(a, b)
            if b.endswith("app-1.0.0"): ab(b, b"EVIL")
        pkg = self.pkg(); man = self.sign(pkg); c = self.client()
        with mock.patch("updater.os.replace", side_effect=replace_then_tamper):
            r = c.apply(pkg, man)
        self.assertIn("changed immediately after install", r.reason)
        self.assertFalse(os.path.exists(os.path.join(self.inst, "app-1.0.0")))
        self.assertTrue(c.apply(pkg, man).ok)  # nothing stuck behind: journal and lock are gone

    def test_package_changed_between_verification_and_staging_is_detected(self):
        pkg = self.pkg(); man = self.sign(pkg)
        def tamper(ctx):  # runs inside verification, after the hash check but before staging
            ab(pkg, b"changed late"); return "late tamper", "ok"
        r = self.client().apply(pkg, man) if False else None
        c = self.client(extra_checks=[tamper]); res = c.apply(pkg, man)
        self.assertIn("package changed during install", res.reason)
        self.assertEqual([f for f in os.listdir(self.inst) if not f.startswith(".")], [])

    def test_similarly_named_package_does_not_confuse_version_lookup(self):
        os.makedirs(self.inst, exist_ok=True); os.chmod(self.inst, 0o700); wb(os.path.join(self.inst, "app-cli-9.0.0"), b"x")
        pkg = self.pkg(); self.assertTrue(self.client().apply(pkg, self.sign(pkg)).ok)

    def test_hostile_manifest_names_never_touch_files_outside_the_install_dir(self):
        for bad in ("../escape", "..\\escape", "/tmp/escape", "a/../../escape", "app\x00x"):
            pkg = self.pkg(); m = create_release(pkg, self.key, "Acme", "1.0.0", package_name="app")["manifest"]; m["package"] = bad
            out = pkg + ".hostile.json"
            wj(out, {"manifest": m, "alg": "ed25519", "signature": base64.b64encode(sign_bytes(self.key, canonical(m))).decode()})
            self.assertFalse(self.client().apply(pkg, out).ok, repr(bad))
        self.assertFalse(os.path.exists(self.p("escape"))); self.assertFalse(os.path.exists("/tmp/escape"))

    def test_private_key_files_are_owner_only(self):
        p = self.p("k.key"); wt(p, "old"); os.chmod(p, 0o666); write_private(p, "new")
        self.assertEqual(os.stat(p).st_mode & 0o777, 0o600)


# =====================================================================================
# 2. CRASH RECOVERY
# =====================================================================================
class CrashRecovery(Base):
    def crash_state_write(self, pkg, man):
        """Kill the process after the rename but before state.json is written."""
        real = updater.atomic_write
        def maybe_crash(path, text):
            if path == self.state: raise Crash()
            return real(path, text)
        with mock.patch("updater.atomic_write", side_effect=maybe_crash):
            with self.assertRaises(Crash):
                self.client().apply(pkg, man)

    def test_crash_after_rename_before_state_is_finished_by_recover(self):
        pkg = self.pkg(); man = self.sign(pkg); self.crash_state_write(pkg, man)
        self.assertTrue(os.path.exists(os.path.join(self.inst, "app-1.0.0")))
        self.assertTrue(os.path.exists(os.path.join(self.inst, ".update.journal")))
        self.assertFalse(os.path.exists(self.state))
        ok, msgs = self.client().recover(); self.assertTrue(ok); self.assertIn("completed an interrupted install", msgs[0])
        self.assertEqual(rj(self.state)["app"]["version"], "1.0.0"); self.assertEqual(self.client().status()[0]["status"], "ok")
        self.assertFalse(os.path.exists(os.path.join(self.inst, ".update.journal")))

    def test_next_update_recovers_automatically_then_installs(self):
        pkg = self.pkg(); self.crash_state_write(pkg, self.sign(pkg, "1.0.0"))
        pkg2 = self.pkg("b.bin"); r = self.client().apply(pkg2, self.sign(pkg2, "2.0.0"))
        self.assertTrue(r.ok, r.reason); self.assertEqual(r.steps[0][0], "recovered")
        self.assertEqual(rj(self.state)["app"]["version"], "2.0.0")

    def test_replaying_the_old_version_after_such_a_crash_is_still_blocked(self):
        pkg = self.pkg(); man = self.sign(pkg, "1.0.0"); self.crash_state_write(pkg, man)
        self.assertIn("rollback", self.client().apply(pkg, man).reason)  # the installed file remembers even with no state

    def test_crash_before_rename_installs_nothing_and_can_be_retried(self):
        pkg = self.pkg(); man = self.sign(pkg)
        real_replace = os.replace
        def crash_on_install(a, b):
            if b.endswith("app-1.0.0"): raise Crash()   # os is shared with atomic_write, so only crash the install rename
            return real_replace(a, b)
        with mock.patch("updater.os.replace", side_effect=crash_on_install):
            with self.assertRaises(Crash): self.client().apply(pkg, man)
        self.assertFalse(os.path.exists(os.path.join(self.inst, "app-1.0.0")))
        ok, msgs = self.client().recover(); self.assertTrue(ok); self.assertIn("discarded", msgs[0])
        self.assertTrue(self.client().apply(pkg, man).ok)

    def test_leftover_temp_files_are_cleaned(self):
        c = self.client(); wb(os.path.join(self.inst, ".tmp-abc.part"), b"partial")
        ok, msgs = c.recover(); self.assertTrue(ok); self.assertFalse(os.path.exists(os.path.join(self.inst, ".tmp-abc.part")))

    def test_corrupt_or_forged_journals_block_instead_of_guessing(self):
        c = self.client(); jp = os.path.join(self.inst, ".update.journal"); pkg = self.pkg(); man = self.sign(pkg)
        good = {"package": "app", "version": "1.0.0", "sha256": "0" * 64, "key_id": "0" * 16, "time": iso(now_utc())}
        for bad in ("{nope", "[]", json.dumps({**good, "package": "../x"}), json.dumps({**good, "version": "x"}),
                    json.dumps({**good, "sha256": "zz"}), json.dumps({k: v for k, v in good.items() if k != "key_id"})):
            wt(jp, bad); r = c.apply(pkg, man)
            self.assertFalse(r.ok, bad); self.assertIn("journal is corrupt", r.reason); self.assertFalse(os.path.exists(os.path.join(self.inst, "app-1.0.0")))
        os.remove(jp); self.assertTrue(c.apply(pkg, man).ok)

    def test_journal_that_disagrees_with_the_installed_file_is_not_trusted(self):
        c = self.client(); wb(os.path.join(self.inst, "app-1.0.0"), b"something else")
        wj(os.path.join(self.inst, ".update.journal"), {"package": "app", "version": "1.0.0", "sha256": "0" * 64, "key_id": "0" * 16, "time": iso(now_utc())})
        ok, msgs = c.recover(); self.assertFalse(ok); self.assertIn("does not match the journal", msgs[-1]); self.assertFalse(os.path.exists(self.state))

    def test_state_says_newer_but_file_missing_still_blocks_rollback(self):
        pkg = self.pkg(); c = self.client(); self.assertTrue(c.apply(pkg, self.sign(pkg, "2.0.0")).ok)
        os.remove(os.path.join(self.inst, "app-2.0.0")); self.assertEqual(c.status()[0]["status"], "MISSING")
        self.assertIn("rollback", c.apply(pkg, self.sign(pkg, "1.5.0")).reason)

    def test_state_write_failure_leaves_a_recoverable_install_not_a_half_state(self):
        pkg = self.pkg(); man = self.sign(pkg); real = updater.atomic_write
        def fail_state(path, text):
            if path == self.state: raise OSError("disk full")
            return real(path, text)
        with mock.patch("updater.atomic_write", side_effect=fail_state):
            r = self.client().apply(pkg, man)
        self.assertIn("install failed", r.reason)
        ok, msgs = self.client().recover(); self.assertTrue(ok); self.assertEqual(rj(self.state)["app"]["version"], "1.0.0")


# =====================================================================================
# 3. LOCKS
# =====================================================================================
class LockHandling(Base):
    def dead_pid(self):
        p = subprocess.Popen([sys.executable, "-c", "pass"]); p.wait(); return p.pid

    def plant(self, **over):
        self.client(); info = {"pid": os.getpid(), "host": socket.gethostname(), "time": iso(now_utc()), "token": "t0"}; info.update(over)
        wj(os.path.join(self.inst, ".update.lock"), info)

    def test_lock_records_owner_and_is_removed_afterwards(self):
        seen = {}
        def peek(ctx):
            seen.update(rj(os.path.join(self.inst, ".update.lock"))); return "peek", "ok"
        pkg = self.pkg(); self.assertTrue(self.client(extra_checks=[peek]).apply(pkg, self.sign(pkg)).ok)
        self.assertEqual(seen["pid"], os.getpid()); self.assertEqual(seen["host"], socket.gethostname()); self.assertTrue(seen["token"])
        self.assertFalse(os.path.exists(os.path.join(self.inst, ".update.lock")))

    def test_lock_states(self):
        self.client(); self.assertIsNone(updater.lock_status(self.inst))
        self.plant(); self.assertEqual(updater.lock_status(self.inst)["state"], "held")
        self.plant(pid=self.dead_pid()); self.assertEqual(updater.lock_status(self.inst)["state"], "stale")
        self.plant(host="some-other-machine"); self.assertEqual(updater.lock_status(self.inst)["state"], "other-host")
        wt(os.path.join(self.inst, ".update.lock"), ""); self.assertEqual(updater.lock_status(self.inst)["state"], "unreadable")
        wt(os.path.join(self.inst, ".update.lock"), '{"pid": "x"}'); self.assertEqual(updater.lock_status(self.inst)["state"], "unreadable")

    def test_old_lock_is_not_stale_just_because_it_is_old(self):
        self.plant(time=iso(now_utc() - timedelta(days=400))); self.assertEqual(updater.lock_status(self.inst)["state"], "held")
        ok, msg = updater.break_lock(self.inst); self.assertFalse(ok); self.assertIn("NOT removed", msg)

    def test_break_lock_policy(self):
        self.plant(pid=self.dead_pid()); self.assertTrue(updater.break_lock(self.inst)[0])
        for odd in ({"host": "elsewhere"}, {}):
            self.plant(**odd); self.assertFalse(updater.break_lock(self.inst)[0]); self.assertTrue(updater.break_lock(self.inst, force=True)[0])
        wt(os.path.join(self.inst, ".update.lock"), ""); self.assertFalse(updater.break_lock(self.inst)[0])

    def test_stale_lock_blocks_update_until_broken(self):
        self.plant(pid=self.dead_pid()); pkg = self.pkg(); man = self.sign(pkg)
        r = self.client().apply(pkg, man); self.assertIn("lock-break", r.reason); self.assertIn("stale", r.reason)
        updater.break_lock(self.inst); self.assertTrue(self.client().apply(pkg, man).ok)

    def test_lock_taken_over_by_someone_else_is_not_deleted_by_us(self):
        def hijack(ctx):  # while we work, the lock is legitimately replaced by another owner
            wj(os.path.join(self.inst, ".update.lock"), {"pid": 1, "host": "x", "time": iso(now_utc()), "token": "other"}); return "x", "ok"
        pkg = self.pkg(); self.client(extra_checks=[hijack]).apply(pkg, self.sign(pkg))
        self.assertEqual(rj(os.path.join(self.inst, ".update.lock"))["token"], "other")

    def test_lock_released_after_every_kind_of_failure(self):
        pkg = self.pkg(); c = self.client(); lock = os.path.join(self.inst, ".update.lock")
        c.apply(pkg, self.p("missing.json")); self.assertFalse(os.path.exists(lock))
        ab(pkg, b"x"); c.apply(pkg, self.sign(self.pkg("other"))); self.assertFalse(os.path.exists(lock))
        def boom(ctx): raise Block("no")
        UpdateClient(self.trust, self.state, self.inst, extra_checks=[boom]).apply(self.pkg("p3"), self.sign(self.pkg("p3"))); self.assertFalse(os.path.exists(lock))

    def test_parallel_updates_are_serialised_and_leave_a_consistent_result(self):
        jobs = []
        for v in ("1.0.0", "2.0.0", "3.0.0", "4.0.0"):
            pkg = self.pkg(f"p{v}"); jobs.append((pkg, self.sign(pkg, v), v))
        self.client(); results, gate = {}, threading.Barrier(len(jobs))
        def work(pkg, man, v):
            gate.wait(); results[v] = self.client().apply(pkg, man)
        ts = [threading.Thread(target=work, args=j) for j in jobs]; [t.start() for t in ts]; [t.join() for t in ts]
        okv = sorted(v for v, r in results.items() if r.ok); self.assertTrue(okv, "at least one update must win")
        for v, r in results.items():
            if not r.ok: self.assertTrue("holds the lock" in r.reason or "rollback" in r.reason, r.reason)
        left = sorted(os.listdir(self.inst)); self.assertEqual([f for f in left if f.startswith(".")], [], left)
        self.assertEqual(rj(self.state)["app"]["version"], max(okv, key=parse_version))
        self.assertTrue(all(row["status"] == "ok" for row in self.client().status()))


# =====================================================================================
# 4. AUDIT POLICY
# =====================================================================================
class AuditPolicy(Base):
    def setUp(self):
        super().setUp(); self.log = self.p("audit.log"); self.pk = self.pkg(); self.man = self.sign(self.pk)

    def v(self, **kw):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            r = verify_release(self.pk, self.man, self.trust, audit_log=self.log, **kw)
        return r, err.getvalue()

    def test_required_policy_fails_closed_when_the_log_cannot_be_written(self):
        r, _ = self.v(audit_required=True); self.assertTrue(r.ok)
        with mock.patch("core.os.fsync", side_effect=OSError(28, "No space left on device")):   # written but not durable
            r, _ = self.v(audit_required=True)
        self.assertFalse(r.ok); self.assertIn("audit-required policy", r.reason)
        with mock.patch("core.os.fsync", side_effect=OSError(28, "No space left on device")):
            r, warn = self.v()
        self.assertTrue(r.ok); self.assertIn("WARNING", warn)

    def test_missing_audit_directory(self):
        self.log = self.p("nodir", "audit.log")
        self.assertFalse(self.v(audit_required=True)[0].ok); r, warn = self.v(); self.assertTrue(r.ok); self.assertIn("WARNING", warn)

    @unittest.skipIf(IS_ROOT or not POSIX, "root ignores read-only permissions")
    def test_read_only_audit_log(self):
        self.v(); os.chmod(self.log, 0o400)
        self.assertFalse(self.v(audit_required=True)[0].ok); self.assertTrue(self.v()[0].ok)

    def test_corrupted_log_tail_blocks_when_required_and_is_flagged_otherwise(self):
        self.v(); ab(self.log, b'{"truncated": tru')
        r, _ = self.v(audit_required=True); self.assertFalse(r.ok); self.assertIn("corrupted", r.reason)
        r, _ = self.v(); self.assertTrue(r.ok); ok, n, msg = verify_audit_log(self.log); self.assertFalse(ok)  # detected on audit

    def test_tampering_is_detected_in_every_position(self):
        for _ in range(4): self.v()
        lines = rt(self.log).splitlines()
        for i in range(len(lines)):
            rec = json.loads(lines[i]); rec["allowed"] = not rec["allowed"]
            mod = lines[:i] + [json.dumps(rec)] + lines[i + 1:]; wt(self.log, "\n".join(mod) + "\n")
            self.assertFalse(verify_audit_log(self.log)[0], i)
            wt(self.log, "\n".join(lines[:i] + lines[i + 1:]) + "\n")
            if i < len(lines) - 1: self.assertFalse(verify_audit_log(self.log)[0], f"removed {i}")  # removing the LAST record is the documented limit
        wt(self.log, "\n".join(lines) + "\n"); self.assertTrue(verify_audit_log(self.log)[0])

    def test_install_results_are_chained_into_the_log(self):
        c = self.client(audit_log=self.log, audit_required=True); self.assertTrue(c.apply(self.pk, self.man).ok)
        rows = [json.loads(l) for l in rt(self.log).splitlines()]
        self.assertEqual([r.get("event") for r in rows], [None, "installed"]); self.assertTrue(verify_audit_log(self.log)[0])

    def test_failed_install_after_an_allowed_decision_is_recorded_as_failed(self):
        real = updater.atomic_write
        def fail_state(path, text):
            if path == self.state: raise OSError("disk full")
            return real(path, text)
        c = self.client(audit_log=self.log)
        with mock.patch("updater.atomic_write", side_effect=fail_state): r = c.apply(self.pk, self.man)
        self.assertFalse(r.ok); rows = [json.loads(l) for l in rt(self.log).splitlines()]
        self.assertTrue(rows[0]["allowed"]); self.assertEqual(rows[1]["event"], "install-failed")


# =====================================================================================
# 5. PARSER / METADATA FUZZING
# =====================================================================================
JUNK = [None, 0, -1, 2 ** 70, 1.5, True, "", "x" * 400, [], {}, [None], {"a": 1}, "\u0000", "0" * 64, "\u00fc", ["a"] * 50]

def paths(node, prefix=()):
    yield prefix
    if isinstance(node, dict):
        for k, v in node.items(): yield from paths(v, prefix + (k,))
    elif isinstance(node, list):
        for i, v in enumerate(node[:6]): yield from paths(v, prefix + (i,))

def get(doc, path):
    for k in path: doc = doc[k]
    return doc

def variants(doc, skip=lambda path: False):
    """Every single-node replacement with a junk value, plus every deletion."""
    for path in paths(doc):
        if not path or skip(path): continue
        for junk in JUNK:
            d = copy.deepcopy(doc); parent = get(d, path[:-1])
            if parent[path[-1]] == junk and type(parent[path[-1]]) is type(junk): continue
            parent[path[-1]] = copy.deepcopy(junk); yield d
        d = copy.deepcopy(doc); parent = get(d, path[:-1])
        if isinstance(parent, dict): del parent[path[-1]]; yield d

def byte_mutations(data, rng, n):
    for _ in range(n):
        b = bytearray(data)
        for _ in range(rng.choice((1, 1, 2, 3))):
            pos = rng.randrange(len(b)); mode = rng.choice("fdit")
            if mode == "f": b[pos] = rng.randrange(256)
            elif mode == "d": del b[pos]
            elif mode == "i": b.insert(pos, rng.randrange(256))
            else: b = b[:pos]
            if not b: b = bytearray(b"{")
        yield bytes(b)


class Fuzzing(Base):
    def setUp(self):
        super().setUp(); self.rng = random.Random(1234)
        self.root = generate_key(); TrustStore(self.trust).add("Root", self.root.public_key(), usage=["delegate"])
        self.auth = generate_key(); TrustStore(self.trust).add("Auth", self.auth.public_key(), usage=["revocation"])
        self.logk = generate_key(); TrustStore(self.trust).add("Log", self.logk.public_key(), usage=["log"])
        self.leaf = generate_key(); self.cert = create_delegation(self.root, self.leaf.public_key(), "Release", packages=["app*"], max_depth=0)
        self.pk = self.pkg()

    # ---- release envelope (with certificate chain) ----
    def test_release_envelope_type_fuzzing(self):
        original = create_release(self.pk, self.leaf, "Acme", "1.0.0", package_name="app", chain=[self.cert], embed_pubkey=True)
        out = self.p("e.json"); wj(out, original); self.assertTrue(verify_release(self.pk, out, self.trust).ok)
        count = 0
        for doc in variants(original):
            wj(out, doc); r = verify_release(self.pk, out, self.trust); count += 1   # must never raise
            if r.ok:
                self.assertEqual((doc["manifest"], doc["signature"], doc["chain"]), (original["manifest"], original["signature"], original["chain"]))
        self.assertGreater(count, 300)

    def test_release_envelope_byte_fuzzing(self):
        original = create_release(self.pk, self.leaf, "Acme", "1.0.0", package_name="app", chain=[self.cert]); out = self.p("e.json"); wj(out, original)
        raw = rb(out)
        for data in byte_mutations(raw, self.rng, 600):
            wb(out, data); r = verify_release(self.pk, out, self.trust)
            if r.ok:
                self.assertEqual(json.loads(data)["manifest"], original["manifest"]); self.assertEqual(json.loads(data)["signature"], original["signature"])

    def test_certificate_fields_type_fuzzing(self):
        for doc in variants(self.cert):
            env = create_release(self.pk, self.leaf, "Acme", "1.0.0", package_name="app", chain=[doc]); out = self.p("e.json"); wj(out, env)
            r = verify_release(self.pk, out, self.trust)
            if r.ok: self.assertEqual(doc, self.cert)

    # ---- trust store ----
    def test_trust_store_type_fuzzing(self):
        TrustStore(self.trust).add("Signer", self.key.public_key()); good = rj(self.trust)
        man = self.sign(self.pk)
        sec = lambda r: (r["key_id"], r["alg"], r["public_key"], r["fingerprint"], r["not_before"], r["not_after"], r["revoked"], usage_of(r))
        orig = {r["key_id"]: sec(r) for r in good["publishers"]}; n = 0
        for doc in variants(good):
            wj(self.trust, doc); r = verify_release(self.pk, man, self.trust); n += 1
            if r.ok:
                mine = [x for x in doc["publishers"] if isinstance(x, dict) and x.get("key_id") == key_id_of(self.key.public_key())]
                self.assertEqual([sec(x) for x in mine], [orig[key_id_of(self.key.public_key())]])
        self.assertGreater(n, 300)

    def test_trust_store_byte_fuzzing(self):
        TrustStore(self.trust).add("Signer", self.key.public_key()); raw = rb(self.trust); man = self.sign(self.pk)
        for data in byte_mutations(raw, self.rng, 400):
            wb(self.trust, data); verify_release(self.pk, man, self.trust)   # must never raise
        wb(self.trust, raw)

    # ---- revocation list ----
    def test_revocation_list_fuzzing(self):
        TrustStore(self.trust).add("Signer", self.key.public_key()); man = self.sign(self.pk)
        good = create_revocation_list(self.auth, [], 1); crl = self.p("c.json"); wj(crl, good)
        self.assertTrue(verify_release(self.pk, man, self.trust, revocation_path=crl).ok)
        for doc in variants(good):
            TrustStore(self.trust)  # fresh numbers each time
            d = rj(self.trust); d["revocation_numbers"] = {}; wj(self.trust, d)
            wj(crl, doc); r = verify_release(self.pk, man, self.trust, revocation_path=crl)
            if r.ok: self.assertEqual(doc, good)
        for data in byte_mutations(json.dumps(good).encode(), self.rng, 300):
            wb(crl, data); verify_release(self.pk, man, self.trust, revocation_path=crl)

    # ---- transparency receipt ----
    def test_transparency_receipt_fuzzing(self):
        TrustStore(self.trust).add("Signer", self.key.public_key()); man = self.sign(self.pk); env = rj(man)
        lg = translog.Log(self.p("l.json")); [lg.append({"n": i}) for i in range(4)]
        idx = lg.append(translog.entry_for(env["manifest"], env["signature"])); good = lg.receipt(idx, self.logk); rc = self.p("rc.json"); wj(rc, good)
        chk = lambda: verify_release(self.pk, man, self.trust, extra_checks=[translog.make_check(rc, self.p("l.json"))])
        self.assertTrue(chk().ok)
        for doc in variants(good):
            d = rj(self.trust); d["log_heads"] = {}; wj(self.trust, d); wj(rc, doc); r = chk()
            if r.ok: self.assertEqual(doc, good)
        for data in byte_mutations(json.dumps(good).encode(), self.rng, 300):
            wb(rc, data); chk()

    def test_corrupt_log_file_never_crashes_the_checker(self):
        TrustStore(self.trust).add("Signer", self.key.public_key()); man = self.sign(self.pk); env = rj(man)
        lg = translog.Log(self.p("l.json")); idx = lg.append(translog.entry_for(env["manifest"], env["signature"])); rc = self.p("rc.json"); wj(rc, lg.receipt(idx, self.logk))
        verify_release(self.pk, man, self.trust, extra_checks=[translog.make_check(rc, self.p("l.json"))])   # remember head
        lg.append({"x": 1}); wj(rc, lg.receipt(idx, self.logk))
        for junk in ("{nope", "[]", '{"entries": 5}', '{"entries": [1, 2]}', ""):
            wt(self.p("bad-log.json"), junk)
            r = verify_release(self.pk, man, self.trust, extra_checks=[translog.make_check(rc, self.p("bad-log.json"))])
            self.assertFalse(r.ok, junk)

    # ---- SBOM and advisories ----
    def test_sbom_and_advisory_fuzzing(self):
        TrustStore(self.trust).add("Signer", self.key.public_key())
        good = sbom.create_cyclonedx("app", "1.0.0", sha256_file(self.pk), [("libfoo", "1.1.0")]); sp = self.p("s.json")
        adv_good = {"vulnerabilities": [{"id": "CVE-1", "component": "libfoo", "severity": "low", "affected_below": "1.2.0"}], "minimum_versions": {"x": "1.0"}}
        ap = self.p("a.json")
        def run():
            out = self.pk + ".sb.json"; wj(out, create_release(self.pk, self.key, "Acme", "1.0.0", package_name="app", sbom_path=sp))
            return verify_release(self.pk, out, self.trust, extra_checks=[sbom.make_check(sp, ap, "critical")])
        wj(sp, good); wj(ap, adv_good); self.assertTrue(run().ok)
        for doc in variants(good): wj(sp, doc); wj(ap, adv_good); run()                 # must never raise
        wj(sp, good)
        for doc in variants(adv_good): wj(ap, doc); run()
        wj(ap, adv_good)
        for data in byte_mutations(json.dumps(good).encode(), self.rng, 200): wb(sp, data); run()
        spdx = {"spdxVersion": "SPDX-2.3", "documentDescribes": ["R"], "packages": [{"SPDXID": "R", "name": "app", "versionInfo": "1.0.0"}, {"name": "l", "versionInfo": "1"}]}
        for doc in variants(spdx): wj(sp, doc); run()

    def test_huge_inputs_are_refused_not_processed(self):
        man = self.sign(self.pk); big = self.p("big"); wt(big, " " * (MAX_MANIFEST_BYTES + 5))
        self.assertIn("too large", verify_release(self.pk, big, self.trust).reason)
        wt(big, "[" * 100000)   # deeply nested JSON
        self.assertFalse(verify_release(self.pk, big, self.trust).ok)
        wt(big, '{"manifest": ' + '{"a":' * 5000 + "1" + "}" * 5000 + "}"); self.assertFalse(verify_release(self.pk, big, self.trust).ok)

    # ---- TUF metadata ----
    def test_tuf_metadata_fuzzing(self):
        repo = tufmeta.Repo(self.p("repo"), self.p("keys")); repo.init({"targets": 2}); art = self.pkg("art"); repo.add_target(art, "app", "1.0.0")
        st = self.p("tuf.json"); tufmeta.Client.trust_root(st, self.p("repo", "root.json"))
        want = tufmeta.Client(st).refresh(self.p("repo")); n = 0
        for name in ("root.json", "timestamp.json", "snapshot.json", "targets.json"):
            path = self.p("repo", name); original = rb(path); doc = json.loads(original)
            for mutated in variants(doc):
                wb(path, json.dumps(mutated, indent=1, sort_keys=True).encode()); n += 1
                try:
                    got = tufmeta.Client(st).refresh(self.p("repo"))
                except Block:
                    continue
                self.assertEqual(got, want, f"{name} mutation was accepted with different content")
            for data in byte_mutations(original, self.rng, 120):
                wb(path, data)
                try:
                    got = tufmeta.Client(st).refresh(self.p("repo"))
                except Block:
                    continue
                self.assertEqual(got, want)
            wb(path, original)
        self.assertGreater(n, 500)

    def test_tuf_trusted_root_fuzzing(self):
        repo = tufmeta.Repo(self.p("repo"), self.p("keys")); repo.init(); good = rj(self.p("repo", "root.json")); st = self.p("tuf.json")
        for doc in variants(good):
            wj(self.p("r.json"), doc)
            try:
                tufmeta.Client.trust_root(st, self.p("r.json"))
            except Block:
                pass   # the only exception allowed to escape
        for data in byte_mutations(json.dumps(good).encode(), self.rng, 200):
            wb(self.p("r.json"), data)
            try:
                tufmeta.Client.trust_root(st, self.p("r.json"))
            except Block:
                pass

    # ---- update-client state ----
    def test_state_file_fuzzing(self):
        TrustStore(self.trust).add("Signer", self.key.public_key()); c = self.client(); self.assertTrue(c.apply(self.pk, self.sign(self.pk, "1.0.0")).ok)
        good = rj(self.state); pk2 = self.pkg("b"); man2 = self.sign(pk2, "2.0.0")
        for doc in variants(good):
            wj(self.state, doc); r = self.client().apply(pk2, man2)               # must return a Result, never raise
            self.assertIsInstance(r.ok, bool)
            if os.path.exists(os.path.join(self.inst, "app-2.0.0")): os.remove(os.path.join(self.inst, "app-2.0.0"))
        wj(self.state, good)

    def test_audit_log_fuzzing(self):
        for _ in range(5): verify_release(self.pk, self.sign(self.pk), self.trust, audit_log=self.p("a.log"))
        raw = rb(self.p("a.log")); lines = raw.decode().splitlines(); log = self.p("m.log")
        for data in byte_mutations(raw, self.rng, 500):
            wb(log, data); ok, n, msg = verify_audit_log(log)       # must never raise
            if ok:
                self.assertEqual([json.loads(l) for l in data.decode(errors="replace").splitlines() if l.strip()], [json.loads(l) for l in lines])
        for junk in (b"", b"\n\n", b"null\n", b"[]\n", b'{"hash": 1}\n', b"\xff\xfe\n"):
            wb(log, junk); verify_audit_log(log)


if __name__ == "__main__":
    unittest.main()
