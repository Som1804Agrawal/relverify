"""TUF-style signed metadata (a simplified model of The Update Framework).
Roles: root (trust anchor, rotates keys), targets (what may be installed), snapshot (pins the targets file),
timestamp (short-lived, pins the snapshot). Each role has keys and a signature threshold. The client defends against:
freeze (expiry), rollback (monotonic versions), mix-and-match (hash-bound snapshot/targets), key compromise
(threshold + root-signed key rotation)."""
import base64, hashlib, json, os, re
from datetime import timedelta
from core import (Block, alg_of, atomic_write, canonical, generate_key, iso, key_id_of, load_private, load_public, now_utc,
                  parse_ts, private_pem, public_pem, sha256_file, sign_bytes, verify_bytes, write_private)

ROLES = ("root", "timestamp", "snapshot", "targets")
SPEC = "relverify-tuf-1"
EXPIRY_DAYS = {"root": 365, "timestamp": 1, "snapshot": 30, "targets": 90}
HEX64 = re.compile(r"[0-9a-f]{64}")
MAX_META_BYTES = 5 * 1024 * 1024

def _dump(obj):  # deterministic bytes: the snapshot/timestamp hashes are over exactly these bytes
    return json.dumps(obj, indent=1, sort_keys=True).encode()

def _write(path, data):
    atomic_write(path, data.decode())

def _read(path):
    if os.path.getsize(path) > MAX_META_BYTES:
        raise Block(f"metadata file {os.path.basename(path)} is too large")
    with open(path, "rb") as f:
        return f.read()

def _signed_doc(signed, signers):
    body = canonical(signed)
    return {"signed": signed, "signatures": [
        {"keyid": key_id_of(s.public_key()), "alg": alg_of(s), "sig": base64.b64encode(sign_bytes(s, body)).decode()}
        for s in signers]}

def _meta_ref(data, version):
    return {"version": version, "sha256": hashlib.sha256(data).hexdigest(), "length": len(data)}

def _base(role, version, now):
    return {"_type": role, "spec": SPEC, "version": version, "expires": iso(now + timedelta(days=EXPIRY_DAYS[role]))}


# ---------------- repository side ----------------
class Repo:
    def __init__(self, repo_dir, keys_dir):
        self.repo, self.keys = repo_dir, keys_dir
        os.makedirs(repo_dir, exist_ok=True); os.makedirs(keys_dir, exist_ok=True)

    def _p(self, name):
        return os.path.join(self.repo, name)

    def _load(self, name):
        with open(self._p(name), "rb") as f:
            return json.loads(f.read())

    def _new_key(self, role):
        k = generate_key("ed25519")
        write_private(os.path.join(self.keys, f"{role}-{key_id_of(k.public_key())}.key"), private_pem(k))
        return k

    def _signers(self, role, root_signed):
        out = []
        for kid in root_signed["roles"][role]["keyids"]:
            with open(os.path.join(self.keys, f"{role}-{kid}.key")) as f:
                out.append(load_private(f.read()))
        return out

    def init(self, thresholds=None, now=None):
        now, thresholds = now or now_utc(), thresholds or {}
        keys, roles = {}, {}
        for role in ROLES:
            ks = [self._new_key(role) for _ in range(thresholds.get(role, 1))]
            for k in ks:
                keys[key_id_of(k.public_key())] = {"alg": alg_of(k), "public_key": public_pem(k.public_key())}
            roles[role] = {"keyids": [key_id_of(k.public_key()) for k in ks], "threshold": thresholds.get(role, 1)}
        root = {**_base("root", 1, now), "keys": keys, "roles": roles}
        doc = _dump(_signed_doc(root, self._signers("root", root)))
        _write(self._p("root.1.json"), doc); _write(self._p("root.json"), doc)
        self._publish({}, now)

    def _publish(self, targets, now=None):
        """Re-sign targets, snapshot and timestamp (each version +1) so they stay consistent."""
        now, root = now or now_utc(), self._load("root.json")["signed"]
        def next_version(name):
            return self._load(name)["signed"]["version"] + 1 if os.path.exists(self._p(name)) else 1
        t = {**_base("targets", next_version("targets.json"), now), "targets": targets}
        tdata = _dump(_signed_doc(t, self._signers("targets", root))); _write(self._p("targets.json"), tdata)
        s = {**_base("snapshot", next_version("snapshot.json"), now), "meta": {"targets.json": _meta_ref(tdata, t["version"])}}
        sdata = _dump(_signed_doc(s, self._signers("snapshot", root))); _write(self._p("snapshot.json"), sdata)
        self._write_timestamp(sdata, s["version"], root, now)

    def _write_timestamp(self, sdata, sversion, root, now):
        v = self._load("timestamp.json")["signed"]["version"] + 1 if os.path.exists(self._p("timestamp.json")) else 1
        ts = {**_base("timestamp", v, now), "meta": {"snapshot.json": _meta_ref(sdata, sversion)}}
        _write(self._p("timestamp.json"), _dump(_signed_doc(ts, self._signers("timestamp", root))))

    def add_target(self, pkg_path, package, version, now=None):
        targets = dict(self._load("targets.json")["signed"]["targets"])
        targets[f"{package}-{version}"] = {"package": package, "version": version,
                                           "sha256": sha256_file(pkg_path), "length": os.path.getsize(pkg_path)}
        self._publish(targets, now)

    def refresh_timestamp(self, now=None):
        """Short-lived timestamp must be re-signed regularly; otherwise clients treat the repo as frozen."""
        root, now = self._load("root.json")["signed"], now or now_utc()
        with open(self._p("snapshot.json"), "rb") as f:
            sdata = f.read()
        self._write_timestamp(sdata, json.loads(sdata)["signed"]["version"], root, now)

    def rotate_key(self, role, now=None):
        """Replace a role's keys. Root version +1, signed by the OLD and the NEW root keys."""
        now = now or now_utc(); old = self._load("root.json")["signed"]
        new = json.loads(json.dumps(old)); new["version"] += 1; new["expires"] = iso(now + timedelta(days=EXPIRY_DAYS["root"]))
        count = old["roles"][role]["threshold"]
        fresh = [self._new_key(role) for _ in range(count)]
        for kid in old["roles"][role]["keyids"]:
            if not any(kid in r["keyids"] for n, r in old["roles"].items() if n != role):
                new["keys"].pop(kid, None)
        for k in fresh:
            new["keys"][key_id_of(k.public_key())] = {"alg": alg_of(k), "public_key": public_pem(k.public_key())}
        new["roles"][role] = {"keyids": [key_id_of(k.public_key()) for k in fresh], "threshold": count}
        signers = self._signers("root", old) + (fresh if role == "root" else [])
        doc = _dump(_signed_doc(new, signers))
        _write(self._p(f"root.{new['version']}.json"), doc); _write(self._p("root.json"), doc)
        if role != "root":
            self._publish(dict(self._load("targets.json")["signed"]["targets"]), now)  # re-sign with the new keys


# ---------------- client side ----------------
def _check_root_schema(r):
    if not isinstance(r, dict):
        raise Block("malformed root metadata")
    if not isinstance(r.get("keys"), dict) or not isinstance(r.get("roles"), dict) or set(r["roles"]) != set(ROLES):
        raise Block("malformed root metadata")
    for kid, k in r["keys"].items():
        if not isinstance(k, dict) or key_id_of(load_public(k["public_key"])) != kid or k.get("alg") != alg_of(load_public(k["public_key"])):
            raise Block("root metadata contains an inconsistent key")
    for role, info in r["roles"].items():
        ids, th = info.get("keyids"), info.get("threshold")
        if not isinstance(ids, list) or len(set(ids)) != len(ids) or not all(i in r["keys"] for i in ids) \
                or type(th) is not int or not 1 <= th <= len(ids):
            raise Block(f"malformed role definition for {role}")

def _verify_role(doc, role, root, now, check_expiry=True):
    """Return the 'signed' part if >= threshold distinct trusted keys signed it, else raise Block."""
    try:
        signed, sigs = doc["signed"], doc["signatures"]
        if signed["_type"] != role or signed["spec"] != SPEC or type(signed["version"]) is not int or signed["version"] < 1:
            raise ValueError("wrong type, spec or version")
        exp = parse_ts(signed["expires"])
        info, body, good = root["roles"][role], canonical(signed), set()
        for s in sigs:
            if s["keyid"] in info["keyids"] and s["keyid"] not in good:
                key = root["keys"][s["keyid"]]
                if s["alg"] == key["alg"] and verify_bytes(load_public(key["public_key"]), base64.b64decode(s["sig"], validate=True), body):
                    good.add(s["keyid"])
    except Block:
        raise
    except Exception as e:
        raise Block(f"malformed {role} metadata: {e}")
    if len(good) < info["threshold"]:
        raise Block(f"{role} metadata has {len(good)} valid signature(s), needs {info['threshold']}")
    if check_expiry and now > exp:
        raise Block(f"{role} metadata expired on {signed['expires']} (possible freeze attack)")
    return signed

def _pinned(data, ref, name):
    if not (isinstance(ref, dict) and type(ref.get("version")) is int and isinstance(ref.get("sha256"), str)
            and HEX64.fullmatch(ref["sha256"]) and type(ref.get("length")) is int):
        raise Block(f"malformed reference to {name}")
    if len(data) != ref["length"] or hashlib.sha256(data).hexdigest() != ref["sha256"]:
        raise Block(f"{name} does not match the hash pinned by the higher-level metadata (mix-and-match)")

class Client:
    """Holds the trusted root and the highest version seen of each role (rollback protection)."""
    def __init__(self, state_path):
        self.path = state_path
        with open(state_path) as f:
            self.state = json.load(f)
        self.pending = None

    @staticmethod
    def trust_root(state_path, root_path, now=None):
        """Out-of-band trust anchor: compare the printed key IDs with the publisher before accepting."""
        now = now or now_utc()
        try:
            doc = json.loads(_read(root_path)); root = doc["signed"]
            _check_root_schema(root); _verify_role(doc, "root", root, now)
        except Block:
            raise
        except (OSError, ValueError, KeyError, TypeError, AttributeError, RecursionError) as e:
            raise Block(f"malformed root metadata: {e}")
        atomic_write(state_path, json.dumps({"root": doc, "versions": {"timestamp": 0, "snapshot": 0, "targets": 0}}, indent=1))
        return {r: i["keyids"] for r, i in root["roles"].items()}

    def refresh(self, repo_dir, now=None):
        now = now or now_utc(); p = lambda n: os.path.join(repo_dir, n)
        try:
            return self._refresh(p, now)
        except (OSError, ValueError, KeyError, TypeError, AttributeError, IndexError, RecursionError) as e:
            raise Block(f"cannot update TUF metadata: {e}")

    def _refresh(self, p, now):
        cur, versions = self.state["root"], dict(self.state["versions"])
        # 1. root: follow root.N+1.json while it exists; each must be signed by the old AND the new root keys
        while os.path.exists(p(f"root.{cur['signed']['version'] + 1}.json")):
            new = json.loads(_read(p(f"root.{cur['signed']['version'] + 1}.json")))
            _check_root_schema(new["signed"])
            old_s = _verify_role(cur, "root", cur["signed"], now, check_expiry=False)
            new_s = _verify_role(new, "root", old_s, now, check_expiry=False)
            if new_s["version"] != old_s["version"] + 1:
                raise Block("root version must increase by exactly one")
            _verify_role(new, "root", new_s, now, check_expiry=False)
            for role in ("timestamp", "snapshot"):  # rotated keys: forget the old version numbers
                if new_s["roles"][role]["keyids"] != old_s["roles"][role]["keyids"]:
                    versions[role] = 0
            cur = new
        root = _verify_role(cur, "root", cur["signed"], now)  # the newest root must not be expired
        # 2. timestamp -> 3. snapshot -> 4. targets, each pinned by the one above
        ts_doc = json.loads(_read(p("timestamp.json")))
        ts = _verify_role(ts_doc, "timestamp", root, now)
        if ts["version"] < versions["timestamp"]:
            raise Block(f"timestamp rollback ({ts['version']} < {versions['timestamp']})")
        sdata = _read(p("snapshot.json")); _pinned(sdata, ts["meta"]["snapshot.json"], "snapshot.json")
        sn = _verify_role(json.loads(sdata), "snapshot", root, now)
        if sn["version"] != ts["meta"]["snapshot.json"]["version"] or sn["version"] < versions["snapshot"]:
            raise Block("snapshot version mismatch or rollback")
        tdata = _read(p("targets.json")); _pinned(tdata, sn["meta"]["targets.json"], "targets.json")
        tg = _verify_role(json.loads(tdata), "targets", root, now)
        if tg["version"] != sn["meta"]["targets.json"]["version"] or tg["version"] < versions["targets"]:
            raise Block("targets version mismatch or rollback")
        if not isinstance(tg["targets"], dict):
            raise Block("malformed targets metadata")
        versions.update(timestamp=ts["version"], snapshot=sn["version"], targets=tg["version"])
        self.pending = {"root": cur, "versions": versions}
        return tg["targets"]

    def save(self):
        if self.pending:
            atomic_write(self.path, json.dumps(self.pending, indent=1)); self.state, self.pending = self.pending, None

def verify_target(targets, name, pkg_path):
    e = targets.get(name)
    if not isinstance(e, dict):
        raise Block(f"{name} is not listed in the signed targets metadata")
    if os.path.getsize(pkg_path) != e["length"] or sha256_file(pkg_path) != e["sha256"]:
        raise Block(f"package does not match the signed targets metadata for {name}")
    return e

def make_check(client, repo_dir):
    """Plug-in check for verify_release(extra_checks=[...]): TUF metadata must also approve this exact package."""
    def check(ctx):
        m = ctx["manifest"]
        targets = client.refresh(repo_dir, ctx["now"])
        entry = verify_target(targets, f"{m['package']}-{m['version']}", ctx["pkg_path"])
        if entry["sha256"] != m["sha256"]:
            raise Block("TUF targets metadata and the release manifest disagree about the package hash")
        ctx["commit"].append(client.save)  # remember new version numbers only if everything passes
        v = client.pending["versions"]
        return "TUF metadata", f"root v{client.pending['root']['signed']['version']}, targets v{v['targets']}, snapshot v{v['snapshot']}, timestamp v{v['timestamp']}"
    return check
