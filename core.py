"""Shared core: manifests, signatures, trust store, and the verification pipeline."""
import base64, fnmatch, hashlib, json, os, re, sys, tempfile, uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa

PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.DIGEST_LENGTH)
VERSION = "4.1.0"
USAGES = ("release", "delegate", "revocation", "log")   # what a key is allowed to be used for
DEFAULT_USAGE = ["release", "delegate", "revocation"]    # legacy trust records without key_usage
OPTIONAL_MANIFEST = ("sbom_sha256",)
MAX_MANIFEST_BYTES = 256 * 1024
REQUIRED = ("package", "publisher", "version", "sha256", "key_id", "timestamp", "expiry")


# ---------- helpers ----------
def now_utc():
    return datetime.now(timezone.utc)

def iso(d):
    return d.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def parse_ts(s):
    d = datetime.fromisoformat(s.replace("Z", "+00:00"))
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)

def canonical(obj):
    """Deterministic JSON bytes: this is exactly what gets signed."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

def parse_version(v):
    v = str(v)
    if len(v) > 50 or v.count(".") >= 10 or not re.fullmatch(r"[0-9]{1,9}(\.[0-9]{1,9})*", v):
        raise ValueError(f"bad version {v[:20]!r}")
    return tuple(int(x) for x in v.split("."))

def atomic_write(path, text):
    d = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(dir=d)
    try:
        with os.fdopen(fd, "w") as f:
            f.write(text); f.flush(); os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise

def write_private(path, text):
    """Write a secret file readable only by its owner (0600 on POSIX)."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(text)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


PKG_RE = re.compile(r"[A-Za-z0-9._-]{1,100}")
WINDOWS_RESERVED = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))}

def validate_manifest(m):
    """Strict schema check. Returns (timestamp, expiry) as datetimes or raises ValueError."""
    if not isinstance(m, dict):
        raise ValueError("manifest must be a JSON object")
    missing = [k for k in REQUIRED if k not in m]
    if missing:
        raise ValueError(f"missing fields {missing}")
    extra = sorted(set(m) - set(REQUIRED) - set(OPTIONAL_MANIFEST))
    if extra:
        raise ValueError(f"unexpected fields {extra}")
    for k in REQUIRED:
        if not isinstance(m[k], str):
            raise ValueError(f"{k} must be a string")
    if "sbom_sha256" in m and not (isinstance(m["sbom_sha256"], str) and re.fullmatch(r"[0-9a-f]{64}", m["sbom_sha256"])):
        raise ValueError("sbom_sha256 must be 64 lowercase hex characters")
    pkg = m["package"]
    if (not PKG_RE.fullmatch(pkg) or set(pkg) == {"."} or pkg.endswith(".")
            or pkg.split(".")[0].upper() in WINDOWS_RESERVED):
        raise ValueError("package name not allowed (letters, digits, . _ - only, max 100)")
    if not 1 <= len(m["publisher"]) <= 100 or any(ord(c) < 32 for c in m["publisher"]):
        raise ValueError("publisher must be 1-100 printable characters")
    if not re.fullmatch(r"[0-9a-f]{16}", m["key_id"]):
        raise ValueError("key_id must be 16 lowercase hex characters")
    if not re.fullmatch(r"[0-9a-f]{64}", m["sha256"]):
        raise ValueError("sha256 must be 64 lowercase hex characters")
    if len(m["version"]) > 50 or m["version"].count(".") >= 10:
        raise ValueError("version too long")
    parse_version(m["version"])
    ts, exp = parse_ts(m["timestamp"]), parse_ts(m["expiry"])
    if exp <= ts:
        raise ValueError("expiry must be after timestamp")
    return ts, exp


# ---------- keys & signatures ----------
def generate_key(alg="ed25519"):
    if alg == "ed25519":
        return ed25519.Ed25519PrivateKey.generate()
    if alg == "rsa-pss":
        return rsa.generate_private_key(65537, 3072)
    raise ValueError("alg must be ed25519 or rsa-pss")

def private_pem(k, passphrase=None):
    enc = (serialization.BestAvailableEncryption(passphrase.encode()) if passphrase
           else serialization.NoEncryption())
    return k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, enc).decode()

def is_encrypted(pem):
    return "ENCRYPTED" in pem.splitlines()[0]

def public_pem(pub):
    return pub.public_bytes(serialization.Encoding.PEM,
                            serialization.PublicFormat.SubjectPublicKeyInfo).decode()

def load_private(pem, passphrase=None):
    return serialization.load_pem_private_key(pem.encode(), passphrase.encode() if passphrase else None)

def load_public(pem):
    return serialization.load_pem_public_key(pem.encode())

def fingerprint(pub):
    der = pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(der).hexdigest()

def key_id_of(pub):
    return fingerprint(pub)[:16]

def alg_of(key):
    if hasattr(key, "alg"):  # external signer (see signers.py)
        return key.alg
    if isinstance(key, (ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey)):
        return "ed25519"
    return "rsa-pss"

def sign_bytes(priv, data):
    if hasattr(priv, "sign_data"):  # external signer: the private key never leaves the device
        return priv.sign_data(data)
    return priv.sign(data) if alg_of(priv) == "ed25519" else priv.sign(data, PSS, hashes.SHA256())

def verify_bytes(pub, sig, data):
    try:
        if alg_of(pub) == "ed25519":
            pub.verify(sig, data)
        else:
            pub.verify(sig, data, PSS, hashes.SHA256())
        return True
    except InvalidSignature:
        return False


# ---------- publisher side: build a signed release ----------
def create_release(pkg_path, priv, publisher, version, package_name=None, days_valid=90,
                   timestamp=None, expiry=None, embed_pubkey=False, chain=None, sbom_path=None):
    ts = timestamp or now_utc()
    manifest = {
        "package": package_name or os.path.basename(pkg_path),
        "publisher": publisher,
        "version": version,
        "sha256": sha256_file(pkg_path),
        "key_id": key_id_of(priv.public_key()),
        "timestamp": iso(ts),
        "expiry": iso(expiry or ts + timedelta(days=days_valid)),
    }
    if sbom_path:  # the signed manifest commits to the SBOM's hash
        manifest["sbom_sha256"] = sha256_file(sbom_path)
    env = {"manifest": manifest, "alg": alg_of(priv),
           "signature": base64.b64encode(sign_bytes(priv, canonical(manifest))).decode()}
    if embed_pubkey:  # only ever used for trust-on-first-use prompts
        env["public_key"] = public_pem(priv.public_key())
    if chain:  # delegation certificates, leaf first (see create_delegation)
        env["chain"] = chain
    return env


# ---------- trust store ----------
class TrustError(Exception):
    pass

def validate_trust_record(r):
    """Every field must be present, well-typed and consistent with the stored public key."""
    if not isinstance(r, dict):
        raise TrustError("trust record must be an object")
    need = {"name", "key_id", "alg", "public_key", "fingerprint", "not_before", "not_after", "revoked"}
    if not need <= set(r):
        raise TrustError(f"incomplete trust record (missing {sorted(need - set(r))})")
    if not isinstance(r["name"], str) or not 1 <= len(r["name"]) <= 200:
        raise TrustError("trust record name is invalid")
    if not isinstance(r["revoked"], bool):
        raise TrustError("trust record revoked flag must be true or false")
    if "key_usage" in r and not (isinstance(r["key_usage"], list) and r["key_usage"] and
                                 all(isinstance(u, str) and u in USAGES for u in r["key_usage"])):
        raise TrustError(f"trust record key_usage must be a non-empty list of {USAGES}")
    pub = load_public(r["public_key"])
    if fingerprint(pub) != r["fingerprint"]:
        raise TrustError(f"trust record {r['key_id']} is corrupt (fingerprint mismatch)")
    if key_id_of(pub) != r["key_id"]:
        raise TrustError("trust record key ID does not match its public key")
    if alg_of(pub) != r["alg"]:
        raise TrustError("trust record algorithm does not match its public key")
    if parse_ts(r["not_before"]) >= parse_ts(r["not_after"]):
        raise TrustError("trust record validity period is empty")

def usage_of(rec):
    return rec.get("key_usage", DEFAULT_USAGE)

class TrustStore:
    """Local JSON file of publisher trust records:
    {name, key_id, alg, public_key(PEM), fingerprint, not_before, not_after, revoked}"""
    def __init__(self, path):
        self.path = path
        self.records = {}
        self.rev_numbers = {}  # signer key_id -> highest revocation-list number seen
        self.log_heads = {}    # transparency log key_id -> {"tree_size", "root_hash"} last seen
        if os.path.exists(path):
            try:
                with open(path) as f:
                    data = json.load(f)
                nums = data.get("revocation_numbers", {})
                if not isinstance(nums, dict) or not all(
                        isinstance(k, str) and type(v) is int and v >= 0 for k, v in nums.items()):
                    raise TrustError("revocation numbers are invalid")
                self.rev_numbers = dict(nums)
                heads = data.get("log_heads", {})
                if not isinstance(heads, dict) or not all(
                        isinstance(h, dict) and type(h.get("tree_size")) is int and h["tree_size"] >= 0
                        and isinstance(h.get("root_hash"), str) and re.fullmatch(r"[0-9a-f]{64}", h["root_hash"])
                        for h in heads.values()):
                    raise TrustError("transparency log heads are invalid")
                self.log_heads = dict(heads)
                for r in data["publishers"]:
                    validate_trust_record(r)
                    if r["key_id"] in self.records:
                        raise TrustError(f"duplicate trust record for key {r['key_id']}")
                    self.records[r["key_id"]] = r
            except TrustError:
                raise
            except (KeyError, TypeError, AttributeError, ValueError) as e:
                raise TrustError(f"trust store is malformed: {e}")

    def get(self, key_id):
        return self.records.get(key_id) if isinstance(key_id, str) else None

    @staticmethod
    def record_for(name, pub, not_before=None, not_after=None, days=365, usage=None):
        """Build a trust record WITHOUT saving it (used for trust-on-first-use)."""
        nb = not_before or now_utc()
        na = not_after or nb + timedelta(days=days)
        return {"name": name, "key_id": key_id_of(pub), "alg": alg_of(pub),
                "public_key": public_pem(pub), "fingerprint": fingerprint(pub),
                "not_before": iso(nb), "not_after": iso(na), "revoked": False,
                "key_usage": list(usage or DEFAULT_USAGE)}

    def add(self, name, pub, not_before=None, not_after=None, days=365, usage=None):
        rec = self.record_for(name, pub, not_before, not_after, days, usage)
        self.records[rec["key_id"]] = rec
        self.save()
        return rec

    def revoke(self, key_id):
        if key_id not in self.records:
            raise TrustError(f"no trust record for key {key_id}")
        self.records[key_id]["revoked"] = True
        self.save()

    def save(self):
        atomic_write(self.path, json.dumps({"publishers": list(self.records.values()),
                                         "revocation_numbers": self.rev_numbers,
                                         "log_heads": self.log_heads}, indent=2))


# ---------- verification ----------
@dataclass
class Result:
    ok: bool = False
    reason: str = ""
    manifest: dict = field(default_factory=dict)
    steps: list = field(default_factory=list)
    alg: str = ""

class Block(Exception):
    pass

def create_delegation(issuer_priv, subject_pub, name, not_before=None, not_after=None, days_valid=180, packages=None, max_depth=None, key_usage=None):
    """Certificate: the issuer vouches for subject_pub for a limited time. Lets a trusted root key
    delegate to short-lived release keys, so only the root has to be in the trust store."""
    nb = not_before or now_utc()
    body = {"subject_key_id": key_id_of(subject_pub), "subject_public_key": public_pem(subject_pub),
            "name": name, "not_before": iso(nb), "not_after": iso(not_after or nb + timedelta(days=days_valid)),
            "issuer_key_id": key_id_of(issuer_priv.public_key())}
    usage = list(key_usage or ["release"])  # least privilege by default
    if not all(u in USAGES for u in usage):
        raise ValueError(f"key_usage must be a subset of {USAGES}")
    body["key_usage"] = usage
    body["serial"] = uuid.uuid4().hex[:16]  # lets one certificate be revoked ("cert:<serial>") without revoking the key
    if packages:  # restrict which package names the delegated key may sign (fnmatch patterns)
        body["packages"] = list(packages)
    if max_depth is not None:  # how many further certificates may be chained BELOW this one (0 = none)
        body["max_depth"] = int(max_depth)
    return {"delegation": body, "alg": alg_of(issuer_priv),
            "signature": base64.b64encode(sign_bytes(issuer_priv, canonical(body))).decode()}

MAX_CHAIN = 3

def resolve_chain(chain, key_id, store, now):
    """Walk the delegation chain from the signing key up to a key in the trust store.
    Returns (record for the signing key, [key IDs on the path incl. the trust anchor]) or raises Block."""
    if not isinstance(chain, list) or not 1 <= len(chain) <= MAX_CHAIN:
        raise Block(f"delegation chain must have 1 to {MAX_CHAIN} certificates")
    expect, ids, nb, na, cons, serials = key_id, [], None, None, [], []
    for i, cert in enumerate(chain):
        try:
            d, sig = cert["delegation"], base64.b64decode(cert["signature"], validate=True)
            subj, issuer, spub = d["subject_key_id"], d["issuer_key_id"], load_public(d["subject_public_key"])
            if not (isinstance(subj, str) and isinstance(issuer, str) and re.fullmatch(r"[0-9a-f]{16}", subj)
                    and re.fullmatch(r"[0-9a-f]{16}", issuer)):
                raise ValueError("key IDs must be 16 hex characters")
            if not isinstance(d.get("name"), str):
                raise ValueError("name must be a string")
            cnb, cna = parse_ts(d["not_before"]), parse_ts(d["not_after"])
            issuer_pem = chain[i + 1]["delegation"]["subject_public_key"] if i + 1 < len(chain) else None
        except Exception as e:
            raise Block(f"malformed delegation certificate: {e}")
        if subj != expect or key_id_of(spub) != subj:
            raise Block("delegation chain is broken (key ID mismatch)")
        md = d.get("max_depth")
        if md is not None:
            if type(md) is not int or md < 0:
                raise Block("malformed delegation certificate: max_depth must be a non-negative integer")
            if i > md:  # i certificates sit below this one
                raise Block("delegation policy violated: this certificate does not allow further delegation")
        usage = d.get("key_usage", ["release", "delegate"])  # certificates made before key_usage existed
        if not (isinstance(usage, list) and usage and all(isinstance(u, str) and u in USAGES for u in usage)):
            raise Block("malformed delegation certificate: key_usage")
        need = "release" if i == 0 else "delegate"
        if need not in usage:
            raise Block(f"key_usage violation: certificate for key {subj} does not allow {need!r}")
        if i == 0:
            leaf_usage = usage
        serial = d.get("serial")
        if serial is not None:
            if not isinstance(serial, str) or not re.fullmatch(r"[0-9a-f]{16}", serial):
                raise Block("malformed delegation certificate: bad serial")
            serials.append("cert:" + serial)
        pk = d.get("packages")
        if pk is not None:
            if not isinstance(pk, list) or not all(isinstance(x, str) for x in pk):
                raise Block("malformed delegation certificate: packages must be a list of strings")
            cons.append(pk)
        if issuer_pem is None:  # last certificate: issuer must be a trusted key
            anchor = store.get(issuer)
            if anchor is None:
                raise Block("delegation chain does not lead to a trusted key")
            if anchor["revoked"]:
                raise Block("trust anchor key is revoked")
            if "delegate" not in usage_of(anchor):
                raise Block("trust anchor key is not authorised to delegate (key_usage)")
            issuer_pem = anchor["public_key"]
            cnb, cna = max(cnb, parse_ts(anchor["not_before"])), min(cna, parse_ts(anchor["not_after"]))
        try:
            ipub = load_public(issuer_pem)
            ok = cert.get("alg") == alg_of(ipub) and verify_bytes(ipub, sig, canonical(d))
        except Exception as e:
            raise Block(f"malformed delegation certificate: {e}")
        if not ok:
            raise Block("delegation certificate has a bad signature")
        nb, na = max(nb or cnb, cnb), min(na or cna, cna)
        ids.append(subj); expect = issuer
    ids.append(expect)
    leaf = chain[0]["delegation"]
    return {"name": leaf["name"], "alg": alg_of(load_public(leaf["subject_public_key"])),
            "public_key": leaf["subject_public_key"], "not_before": iso(nb), "not_after": iso(na),
            "revoked": False, "key_usage": leaf_usage}, ids, cons, serials


REVOKE_ID_RE = re.compile(r"(cert:)?[0-9a-f]{16}")
MAX_CRL_BYTES = 1024 * 1024
MAX_CRL_ENTRIES = 10000

def create_revocation_list(priv, revoked_ids, number, days_valid=30, issued=None):
    """A revocation list signed by a trusted key: {revocations:{number,issued,expiry,revoked,key_id}, alg, signature}"""
    t = issued or now_utc()
    if type(number) is not int or number < 0:
        raise ValueError("revocation list number must be a non-negative integer")
    bad = [r for r in revoked_ids if not REVOKE_ID_RE.fullmatch(str(r))]
    if bad:
        raise ValueError(f"not a key ID (16 hex) or cert:SERIAL: {bad[:3]}")
    body = {"number": number, "issued": iso(t), "expiry": iso(t + timedelta(days=days_valid)),
            "revoked": sorted(revoked_ids), "key_id": key_id_of(priv.public_key())}
    return {"revocations": body, "alg": alg_of(priv),
            "signature": base64.b64encode(sign_bytes(priv, canonical(body))).decode()}

def load_revocation_list(path, store, now=None, max_age_days=None):
    """Return the set of revoked key IDs, or raise Block if the list cannot be trusted."""
    now = now or now_utc()
    try:
        if os.path.getsize(path) > MAX_CRL_BYTES:
            raise ValueError("file too large")
        with open(path) as f:
            env = json.load(f)
        if set(env) != {"revocations", "alg", "signature"}:
            raise ValueError("unexpected or missing envelope fields")
        body, sig = env["revocations"], base64.b64decode(env["signature"], validate=True)
        if set(body) != {"number", "issued", "expiry", "revoked", "key_id"}:
            raise ValueError("unexpected or missing list fields")
        signer, number = body["key_id"], body["number"]
        if not isinstance(signer, str) or not re.fullmatch(r"[0-9a-f]{16}", signer):
            raise ValueError("signer key_id is invalid")
        if type(number) is not int or number < 0:
            raise ValueError("number must be a non-negative integer")
        if not isinstance(body["revoked"], list) or len(body["revoked"]) > MAX_CRL_ENTRIES:
            raise ValueError("revoked must be a list of at most %d entries" % MAX_CRL_ENTRIES)
        if not all(isinstance(r, str) and REVOKE_ID_RE.fullmatch(r) for r in body["revoked"]):
            raise ValueError("revoked entries must be key IDs (16 hex) or cert:SERIAL")
        issued, expiry, ids = parse_ts(body["issued"]), parse_ts(body["expiry"]), set(body["revoked"])
        if expiry <= issued:
            raise ValueError("expiry must be after issued")
    except Exception as e:
        raise Block(f"malformed revocation list: {e}")
    rec = store.get(signer)
    if rec is None:
        raise Block("revocation list signed by an unknown key")
    if rec["revoked"] or not parse_ts(rec["not_before"]) <= now <= parse_ts(rec["not_after"]):
        raise Block("revocation list signer key is not valid")
    if "revocation" not in usage_of(rec):
        raise Block("revocation list signer is not authorised for revocation (key_usage)")
    if env.get("alg") != rec["alg"] or not verify_bytes(load_public(rec["public_key"]), sig, canonical(body)):
        raise Block("revocation list has a bad signature")
    if now > expiry:
        raise Block(f"revocation list expired on {body['expiry']}")
    if issued > now + timedelta(minutes=5):
        raise Block("revocation list is dated in the future")
    if max_age_days is not None and now - issued > timedelta(days=max_age_days):
        raise Block(f"revocation list is stale (issued {body['issued']}, policy allows {max_age_days} days)")
    last = store.rev_numbers.get(signer, 0)
    if number < last:
        raise Block(f"revocation list rollback (number {number} is older than {last})")
    if number > last:
        store.rev_numbers[signer] = number
        store.save()
    return ids

GENESIS = "0" * 64

def _last_hash(path, strict=False):
    """Hash of the newest record. strict=True refuses a log whose tail is unreadable instead of restarting the chain."""
    try:
        with open(path) as f:
            lines = [l for l in f if l.strip()]
        if not lines:
            return GENESIS
        h = json.loads(lines[-1]).get("hash")
        if isinstance(h, str) and HEX64_RE.fullmatch(h):
            return h
        raise ValueError("last record has no valid hash")
    except FileNotFoundError:
        return GENESIS
    except (OSError, ValueError, AttributeError) as e:
        if strict:
            raise ValueError(f"audit log tail is unreadable or corrupted ({e})")
        return GENESIS  # lenient mode: chain restarts, and verify_audit_log will flag it

HEX64_RE = re.compile(r"[0-9a-f]{64}")

def _append_audit(path, rec, strict):
    """Chain, write and fsync one record. Returns None on success or a short reason on failure."""
    try:
        rec["prev"] = _last_hash(path, strict)
        rec["hash"] = hashlib.sha256(canonical(rec)).hexdigest()
        with open(path, "a") as f:
            f.write(json.dumps(rec) + "\n"); f.flush(); os.fsync(f.fileno())
        return None
    except (OSError, ValueError) as e:
        return str(e)[:120]

def _audit(path, pkg_path, res, strict=False):
    """Append one hash-chained record per decision. Returns None on success, else the reason it failed."""
    if not path:
        return None
    m = res.manifest
    rec = {"id": str(uuid.uuid4()), "time": iso(now_utc()), "client": VERSION,
           "package": os.path.basename(pkg_path), "manifest_package": m.get("package"), "version": m.get("version"),
           "publisher": m.get("publisher"), "key_id": m.get("key_id"), "alg": res.alg or None,
           "sha256": m.get("sha256"), "allowed": res.ok, "reason": res.reason or "ok",
           "steps": [n for n, _ in res.steps]}
    return _append_audit(path, rec, strict)

def audit_event(path, kind, **data):
    """Record something that happened AFTER the decision (e.g. the install result). Best effort: the state has already
    changed, so a failure here is reported but cannot undo it. Returns None or the failure reason."""
    if not path:
        return None
    rec = {"id": str(uuid.uuid4()), "time": iso(now_utc()), "client": VERSION, "event": kind, **data}
    return _append_audit(path, rec, False)

def verify_audit_log(path):
    """Check the hash chain. Returns (ok, records_checked, message). Detects edited, removed or
    reordered records; deleting records from the END is only detectable against a saved head hash."""
    prev, n = GENESIS, 0
    try:
        with open(path) as f:
            for lineno, line in enumerate(f, 1):
                if not line.strip():
                    continue
                try:
                    rec = json.loads(line)
                    if not isinstance(rec, dict) or not isinstance(rec.get("hash"), str):
                        raise ValueError("not an audit record")
                    h = rec.pop("hash")
                except (ValueError, KeyError, AttributeError, RecursionError):
                    return False, n, f"line {lineno}: not a valid audit record"
                if rec.get("prev") != prev:
                    return False, n, f"line {lineno}: chain broken (a record was removed or reordered)"
                if hashlib.sha256(canonical(rec)).hexdigest() != h:
                    return False, n, f"line {lineno}: record was modified"
                prev, n = h, n + 1
    except (OSError, ValueError) as e:  # ValueError includes undecodable (binary) content
        return False, n, f"cannot read log: {e}"
    return True, n, f"ok, head hash {prev}"

def format_report(res, pkg_path=""):
    """Plain-text verification report (also used by the GUI's Export button)."""
    m = res.manifest
    lines = ["RELEASE VERIFICATION REPORT", "=" * 27, f"Time (UTC):  {iso(now_utc())}",
             f"Result:      {'VERIFIED - safe to install' if res.ok else 'BLOCKED'}"]
    if res.reason:
        lines.append(f"Reason:      {res.reason}")
    lines += [f"File:        {os.path.basename(pkg_path)}", f"Package:     {m.get('package', '-')}",
              f"Version:     {m.get('version', '-')}", f"Publisher:   {m.get('publisher', '-')}",
              f"Key ID:      {m.get('key_id', '-')}", f"Algorithm:   {res.alg or '-'}",
              f"SHA-256:     {m.get('sha256', '-')}", f"Tool:        RelVerify {VERSION}", "", "Checks:"]
    lines += [f"  [{'FAIL' if n == 'BLOCKED' else 'PASS'}] {n}" + (f": {d}" if d != "ok" else "") for n, d in res.steps]
    return "\n".join(lines) + "\n"


def verify_release(pkg_path, manifest_path, trust_path, installed_version=None, tofu=None, now=None,
                   revocation_path=None, audit_log=None, revocation_max_age_days=None,
                   audit_required=False, extra_checks=None):
    """Verification order (any failure blocks):
       1 parse + schema  2 signature vs trust store  3 key validity  4 manifest expiry
       5 rollback check  6 hash of package vs manifest.
    installed_version: callable(package_name) -> version str | None  (Class C)
    tofu: callable(publisher, key_id, fingerprint) -> bool  (Class B first-use prompt)"""
    res, now = Result(), now or now_utc()

    def step(name, detail="ok"):
        res.steps.append((name, detail))

    try:
        # 1. parse
        if os.path.getsize(manifest_path) > MAX_MANIFEST_BYTES:
            raise Block("manifest file too large")
        try:
            with open(manifest_path) as f:
                env = json.load(f)
            m, sig = env["manifest"], base64.b64decode(env["signature"], validate=True)
            extra = sorted(set(env) - {"manifest", "alg", "signature", "public_key", "chain"})
            if extra:
                raise ValueError(f"unexpected envelope fields {extra}")
            if env.get("alg") not in ("ed25519", "rsa-pss"):
                raise ValueError("unsupported signature algorithm")
            ts, exp = validate_manifest(m)
        except Exception as e:
            raise Block(f"malformed manifest: {e}")
        res.manifest = m
        step("parse manifest")

        # 2. signature against trust store
        store = TrustStore(trust_path)
        rec, chain_ids, pending = store.get(m["key_id"]), [], None
        if rec is None and env.get("chain"):
            rec, chain_ids, cons, serials = resolve_chain(env["chain"], m["key_id"], store, now)
            chain_ids = chain_ids + serials  # serial tags are checked against the revocation list too
            for allowed in cons:
                if not any(fnmatch.fnmatchcase(m["package"], pat) for pat in allowed):
                    raise Block(f"delegated key is not allowed to sign package {m['package']!r}")
            step("delegation chain valid", f"{len(env['chain'])} certificate(s) to trusted key {chain_ids[len(env['chain'])]}")
        if rec is None:
            pem = env.get("public_key")
            if not (tofu and pem):
                raise Block(f"unknown signing key {m['key_id']} (not in trust store)")
            pub = load_public(pem)
            if key_id_of(pub) != m["key_id"]:
                raise Block("embedded key does not match key_id")
            if not verify_bytes(pub, sig, canonical(m)):
                raise Block("bad signature (manifest altered or wrong key)")
            if not tofu(m["publisher"], m["key_id"], fingerprint(pub)):
                raise Block("first-use key rejected by user")
            rec = pending = TrustStore.record_for(m["publisher"], pub, usage=["release"])  # NOT saved yet; release-only
            step("trust on first use", f"key {m['key_id']} accepted by user (saved only if every check passes)")
        pub = load_public(rec["public_key"])
        if env["alg"] != rec["alg"]:  # the algorithm comes from the trusted record, never from the file
            raise Block(f"signature algorithm {env['alg']!r} does not match the trusted key ({rec['alg']})")
        if not verify_bytes(pub, sig, canonical(m)):
            raise Block("bad signature (manifest altered or wrong key)")
        if "release" not in usage_of(rec):
            raise Block("key is not authorised to sign releases (key_usage)")
        res.alg = rec["alg"]
        step("signature valid", f"{rec['alg']} by {rec['name']}")

        # 3. key validity
        if rec["revoked"]:
            raise Block("signing key is revoked")
        if now < parse_ts(rec["not_before"]):
            raise Block("signing key not yet valid")
        if now > parse_ts(rec["not_after"]):
            raise Block(f"signing key expired on {rec['not_after']}")
        if ts > now + timedelta(minutes=5):
            raise Block("manifest timestamp is in the future")
        step("signing key valid", f"{rec['not_before']} .. {rec['not_after']}")
        if revocation_path:  # signed revocation list (fails closed if the list is bad)
            if {m["key_id"], *chain_ids} & load_revocation_list(revocation_path, store, now, revocation_max_age_days):
                raise Block("signing key (or a key in its chain) revoked by signed revocation list")
            step("revocation list checked")

        # 4. manifest expiry
        if now > exp:
            raise Block(f"manifest expired on {m['expiry']}")
        step("manifest not expired")

        # 5. rollback (update client only)
        if installed_version:
            cur = installed_version(m["package"])
            if cur and parse_version(m["version"]) <= parse_version(cur):
                raise Block(f"rollback rejected: {m['version']} is not newer than installed {cur}")
            step("version is newer", f"installed={cur}, offered={m['version']}")

        # 6. package hash
        actual = sha256_file(pkg_path)
        if actual != m["sha256"]:
            raise Block(f"hash mismatch (expected {m['sha256'][:12]}..., got {actual[:12]}...)")
        step("package hash matches")
        commits = []  # state changes that are only applied if EVERYTHING passes
        ctx = {"manifest": m, "signature": env["signature"], "pkg_path": pkg_path, "store": store, "now": now, "commit": commits}
        for check in extra_checks or ():  # SBOM, transparency log, TUF metadata, ... (each raises Block to stop)
            name, detail = check(ctx)
            step(name, detail)
        if pending:  # every check passed: now the user's trust decision may be remembered
            store.records[pending["key_id"]] = pending; store.save()
            step("trust record saved", f"publisher {pending['name']} added to trust store")
        for apply in commits:
            apply()
        res.ok = True
    except Block as b:
        res.reason = str(b)
        step("BLOCKED", res.reason)
    except (OSError, TrustError, ValueError) as e:  # fail closed on anything unexpected
        res.reason = f"error: {e}"
        step("BLOCKED", res.reason)
    err = _audit(audit_log, pkg_path, res, strict=audit_required)
    if err:
        if audit_required and res.ok:  # mandatory-logging policy: no durable record, no install (fail closed)
            res.ok, res.reason = False, f"audit log could not be written: {err} (audit-required policy)"
            res.steps.append(("BLOCKED", res.reason))
        else:
            print(f"WARNING: audit log could not be written: {err}", file=sys.stderr)
    return res
