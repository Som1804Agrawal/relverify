"""Transparency log: an append-only Merkle tree (RFC 6962 / RFC 9162 hashing) with signed tree heads,
inclusion proofs and consistency proofs. A release is only trusted if it is provably in the log, so a
publisher (or an attacker with a stolen key) cannot show different releases to different users in secret."""
import base64, hashlib, json, os, re
from core import (Block, canonical, iso, load_public, now_utc, parse_ts, sign_bytes, alg_of, key_id_of,
                  usage_of, verify_bytes, atomic_write)
from datetime import timedelta

def _h(b):
    return hashlib.sha256(b).digest()

def leaf_hash(data):
    return _h(b"\x00" + data)

def node_hash(left, right):
    return _h(b"\x01" + left + right)

def _split(n):  # largest power of two strictly smaller than n
    return 1 << ((n - 1).bit_length() - 1)

def mth(leaves):
    n = len(leaves)
    if n == 0:
        return _h(b"")
    if n == 1:
        return leaves[0]
    k = _split(n)
    return node_hash(mth(leaves[:k]), mth(leaves[k:]))

def inclusion_path(m, leaves):
    n = len(leaves)
    if n == 1:
        return []
    k = _split(n)
    if m < k:
        return inclusion_path(m, leaves[:k]) + [mth(leaves[k:])]
    return inclusion_path(m - k, leaves[k:]) + [mth(leaves[:k])]

def _subproof(m, leaves, whole):
    n = len(leaves)
    if m == n:
        return [] if whole else [mth(leaves)]
    k = _split(n)
    if m <= k:
        return _subproof(m, leaves[:k], whole) + [mth(leaves[k:])]
    return _subproof(m - k, leaves[k:], False) + [mth(leaves[:k])]

def verify_inclusion(leaf, index, size, proof, root):
    if not 0 <= index < size:
        return False
    fn, sn, r = index, size - 1, leaf
    for p in proof:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = node_hash(p, r)
            if not fn & 1:
                while not fn & 1 and fn != 0:
                    fn >>= 1; sn >>= 1
        else:
            r = node_hash(r, p)
        fn >>= 1; sn >>= 1
    return sn == 0 and r == root

def verify_consistency(first, second, first_root, second_root, proof):
    if first > second or first < 0:
        return False
    if first == second:
        return proof == [] and first_root == second_root
    if first == 0:
        return proof == []
    if not proof:
        return False
    if first & (first - 1) == 0:  # power of two: the old root is itself a node of the new tree
        proof = [first_root] + proof
    fn, sn = first - 1, second - 1
    while fn & 1:
        fn >>= 1; sn >>= 1
    fr = sr = proof[0]
    for c in proof[1:]:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            fr, sr = node_hash(c, fr), node_hash(c, sr)
            if not fn & 1:
                while not fn & 1 and fn != 0:
                    fn >>= 1; sn >>= 1
        else:
            sr = node_hash(sr, c)
        fn >>= 1; sn >>= 1
    return fr == first_root and sr == second_root and sn == 0


def entry_for(manifest, signature_b64):
    """What the log records for a release: the signed manifest itself."""
    return {"manifest": manifest, "signature": signature_b64}

class Log:
    """File-backed log. The file is just data: clients never trust it, they check signatures and proofs."""
    def __init__(self, path):
        self.path, self.entries = path, []
        if os.path.exists(path):
            with open(path) as f:
                entries = json.load(f)["entries"]
            if not isinstance(entries, list) or not all(isinstance(e, dict) for e in entries):
                raise ValueError("log file must contain a list of entries")
            self.entries = entries

    def leaves(self, size=None):
        return [leaf_hash(canonical(e)) for e in self.entries[:size]]

    def size(self):
        return len(self.entries)

    def root(self, size=None):
        return mth(self.leaves(size))

    def append(self, entry):
        for i, e in enumerate(self.entries):
            if e == entry:
                return i  # already logged
        self.entries.append(entry)
        atomic_write(self.path, json.dumps({"entries": self.entries}, indent=1))
        return len(self.entries) - 1

    def inclusion_proof(self, index, size=None):
        size = size or self.size()
        return [p.hex() for p in inclusion_path(index, self.leaves(size))]

    def consistency_proof(self, old_size, new_size=None):
        new_size = new_size or self.size()
        return [p.hex() for p in _subproof(old_size, self.leaves(new_size), True)]

    def signed_tree_head(self, signer, size=None):
        size = size or self.size()
        body = {"tree_size": size, "root_hash": self.root(size).hex(), "timestamp": iso(now_utc()),
                "key_id": key_id_of(signer.public_key())}
        return body, base64.b64encode(sign_bytes(signer, canonical(body))).decode(), alg_of(signer)

    def receipt(self, index, signer):
        """Everything a verifier needs offline: proof that entry `index` is in the tree the log signed."""
        sth, sig, alg = self.signed_tree_head(signer)
        return {"leaf_index": index, "tree_size": sth["tree_size"], "proof": self.inclusion_proof(index, sth["tree_size"]),
                "sth": sth, "sth_signature": sig, "alg": alg}


HEX64 = re.compile(r"[0-9a-f]{64}")

def make_check(receipt_path, log_path=None, max_sth_age_days=None):
    """Plug-in check for verify_release(extra_checks=[...]): the release must be provably logged."""
    def check(ctx):
        m, store, now = ctx["manifest"], ctx["store"], ctx["now"]
        try:
            with open(receipt_path) as f:
                rc = json.load(f)
            if set(rc) != {"leaf_index", "tree_size", "proof", "sth", "sth_signature", "alg"}:
                raise ValueError("unexpected or missing receipt fields")
            idx, size, sth = rc["leaf_index"], rc["tree_size"], rc["sth"]
            if type(idx) is not int or type(size) is not int or not 0 <= idx < size:
                raise ValueError("bad leaf index or tree size")
            if set(sth) != {"tree_size", "root_hash", "timestamp", "key_id"} or sth["tree_size"] != size:
                raise ValueError("bad tree head")
            if not isinstance(sth["key_id"], str) or not isinstance(rc["alg"], str):
                raise ValueError("bad key id or algorithm")
            if not isinstance(sth["root_hash"], str) or not HEX64.fullmatch(sth["root_hash"]):
                raise ValueError("bad root hash")
            if not isinstance(rc["proof"], list) or len(rc["proof"]) > 64 or not all(
                    isinstance(p, str) and HEX64.fullmatch(p) for p in rc["proof"]):
                raise ValueError("bad proof")
            sig, sth_time = base64.b64decode(rc["sth_signature"], validate=True), parse_ts(sth["timestamp"])
        except Exception as e:
            raise Block(f"malformed transparency receipt: {e}")
        rec = store.get(sth["key_id"])
        if rec is None or "log" not in usage_of(rec):
            raise Block("receipt is signed by a key that is not a trusted transparency log (needs key_usage 'log')")
        if rec["revoked"] or not parse_ts(rec["not_before"]) <= now <= parse_ts(rec["not_after"]):
            raise Block("transparency log key is not valid")
        if rc["alg"] != rec["alg"] or not verify_bytes(load_public(rec["public_key"]), sig, canonical(sth)):
            raise Block("transparency log signature is bad")
        if sth_time > now + timedelta(minutes=5):
            raise Block("tree head is dated in the future")
        if max_sth_age_days is not None and now - sth_time > timedelta(days=max_sth_age_days):
            raise Block("tree head is too old (policy)")
        leaf = leaf_hash(canonical(entry_for(m, ctx["signature"])))
        if not verify_inclusion(leaf, idx, size, [bytes.fromhex(p) for p in rc["proof"]], bytes.fromhex(sth["root_hash"])):
            raise Block("release is NOT in the transparency log (inclusion proof failed)")
        detail = f"entry #{idx} in a log of {size}"
        # append-only check against the last head this device saw
        head = store.log_heads.get(sth["key_id"])
        if head:
            if size == head["tree_size"] and sth["root_hash"] != head["root_hash"]:
                raise Block("transparency log shows two different trees of the same size (split view)")
            if size > head["tree_size"]:
                if log_path is None:
                    detail += "; consistency not checked (no --log given)"
                else:
                    try:
                        proof = [bytes.fromhex(p) for p in Log(log_path).consistency_proof(head["tree_size"], size)]
                    except (OSError, ValueError, KeyError, TypeError, IndexError, RecursionError) as e:
                        raise Block(f"transparency log file is unusable: {e}")
                    if not verify_consistency(head["tree_size"], size, bytes.fromhex(head["root_hash"]),
                                              bytes.fromhex(sth["root_hash"]), proof):
                        raise Block("transparency log is not append-only (consistency proof failed)")
                    detail += "; append-only vs previous head verified"
        if not head or size > head["tree_size"]:
            def remember():
                store.log_heads[sth["key_id"]] = {"tree_size": size, "root_hash": sth["root_hash"]}; store.save()
            ctx["commit"].append(remember)  # only remembered if the whole verification passes
        return "transparency log", detail
    return check
