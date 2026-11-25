"""SBOM verification. The signed manifest commits to the SBOM's SHA-256, the SBOM must describe THIS package
(name, version, hash), and its components are matched against an offline advisory list to flag vulnerable or
outdated libraries. Supports CycloneDX JSON and SPDX JSON."""
import json, os, re
from core import Block, sha256_file

SEVERITIES = ["low", "medium", "high", "critical"]
MAX_SBOM_BYTES = 10 * 1024 * 1024
MAX_COMPONENTS = 5000
SHA256 = re.compile(r"[0-9a-fA-F]{64}")

def _s(x, what, required=True, maxlen=300):
    if x is None and not required:
        return None
    if not isinstance(x, str) or not x or len(x) > maxlen:
        raise ValueError(f"{what} must be a non-empty string")
    return x

def _hash(items, alg_key, val_key, names):
    for h in items or []:
        if isinstance(h, dict) and str(h.get(alg_key, "")).upper().replace("-", "") in names and isinstance(h.get(val_key), str) \
                and SHA256.fullmatch(h[val_key]):
            return h[val_key].lower()
    return None

def _load_sbom(path):
    """Return {"format", "main": {name, version, sha256|None}, "components": [{name, version|None}]} or raise ValueError."""
    if os.path.getsize(path) > MAX_SBOM_BYTES:
        raise ValueError("SBOM file too large")
    with open(path) as f:
        d = json.load(f)
    if not isinstance(d, dict):
        raise ValueError("SBOM must be a JSON object")
    if d.get("bomFormat") == "CycloneDX":
        main = (d.get("metadata") or {}).get("component")
        if not isinstance(main, dict):
            raise ValueError("CycloneDX SBOM has no metadata.component (the described package)")
        comps = d.get("components", [])
        if not isinstance(comps, list):
            raise ValueError("components must be a list")
        main_out = {"name": _s(main.get("name"), "main component name"), "version": _s(main.get("version"), "main component version"),
                    "sha256": _hash(main.get("hashes"), "alg", "content", {"SHA256"})}
        out = [{"name": _s(c.get("name") if isinstance(c, dict) else None, "component name"),
                "version": _s(c.get("version"), "component version", False)} for c in comps]
        fmt = "CycloneDX " + str(d.get("specVersion", "?"))
    elif str(d.get("spdxVersion", "")).startswith("SPDX-"):
        pk = d.get("packages")
        if not isinstance(pk, list) or not pk:
            raise ValueError("SPDX SBOM has no packages")
        described = (d.get("documentDescribes") or [None])[0]
        mains = [p for p in pk if isinstance(p, dict) and p.get("SPDXID") == described]
        if not mains:
            raise ValueError("SPDX SBOM does not say which package it describes (documentDescribes)")
        main = mains[0]
        main_out = {"name": _s(main.get("name"), "main package name"), "version": _s(main.get("versionInfo"), "main package version"),
                    "sha256": _hash(main.get("checksums"), "algorithm", "checksumValue", {"SHA256"})}
        out = [{"name": _s(p.get("name"), "package name"), "version": _s(p.get("versionInfo"), "package version", False)}
               for p in pk if isinstance(p, dict) and p is not main]
        fmt = str(d["spdxVersion"])
    else:
        raise ValueError("unsupported SBOM (need CycloneDX JSON or SPDX JSON)")
    if len(out) > MAX_COMPONENTS:
        raise ValueError("too many components")
    return {"format": fmt, "main": main_out, "components": out}

def load_sbom(path):
    try:
        return _load_sbom(path)
    except (AttributeError, TypeError, KeyError, IndexError, RecursionError) as e:
        raise ValueError(f"malformed SBOM structure ({type(e).__name__})")

def load_advisories(path):
    try:
        return _load_advisories(path)
    except (AttributeError, TypeError, KeyError, IndexError, RecursionError) as e:
        raise ValueError(f"malformed advisory structure ({type(e).__name__})")

def create_cyclonedx(name, version, pkg_sha256, components):
    """Small helper that writes a valid CycloneDX document (components: [(name, version), ...])."""
    return {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
            "metadata": {"component": {"type": "application", "name": name, "version": version,
                                       "hashes": [{"alg": "SHA-256", "content": pkg_sha256}]}},
            "components": [{"type": "library", "name": n, "version": v} for n, v in components]}

def vkey(v):
    """Comparable tuple from the numeric prefix of a version ('2.4.1-beta' -> (2,4,1)); None if there is none."""
    mt = re.match(r"v?(\d+(?:\.\d+){0,9})", v or "")
    return tuple(int(x) for x in mt.group(1).split(".")) if mt else None

def _load_advisories(path):
    with open(path) as f:
        d = json.load(f)
    if not isinstance(d, dict) or set(d) - {"vulnerabilities", "minimum_versions"}:
        raise ValueError("advisory file must have only 'vulnerabilities' and 'minimum_versions'")
    vulns, mins = d.get("vulnerabilities", []), d.get("minimum_versions", {})
    if not isinstance(vulns, list) or not isinstance(mins, dict):
        raise ValueError("bad advisory file structure")
    for v in vulns:
        if not isinstance(v, dict) or v.get("severity") not in SEVERITIES:
            raise ValueError(f"advisory needs a severity from {SEVERITIES}")
        _s(v.get("id"), "advisory id"); _s(v.get("component"), "advisory component")
        if not (v.get("affected_below") or v.get("affected_versions")):
            raise ValueError(f"advisory {v['id']} needs affected_below or affected_versions")
        if v.get("affected_below") and vkey(v["affected_below"]) is None:
            raise ValueError(f"advisory {v['id']}: affected_below is not a version")
        if not all(isinstance(x, str) for x in v.get("affected_versions", [])):
            raise ValueError(f"advisory {v['id']}: affected_versions must be strings")
    for name, ver in mins.items():
        if not isinstance(name, str) or vkey(ver if isinstance(ver, str) else "") is None:
            raise ValueError("minimum_versions must map component names to versions")
    return {"vulnerabilities": vulns, "minimum_versions": {k.lower(): v for k, v in mins.items()}}

def scan(components, adv):
    """Findings: vulnerable components (by advisory) and outdated ones (below the minimum version)."""
    found = []
    for c in components:
        name, ver = c["name"].lower(), c["version"]
        for v in adv["vulnerabilities"]:
            if v["component"].lower() != name:
                continue
            hit = ver in v.get("affected_versions", []) or (
                v.get("affected_below") and (vkey(ver) is None or vkey(ver) < vkey(v["affected_below"])))
            if hit:
                found.append({"kind": "vulnerable", "id": v["id"], "component": c["name"], "version": ver or "unknown",
                              "severity": v["severity"], "fixed_in": v.get("fixed_in") or v.get("affected_below")})
        mn = adv["minimum_versions"].get(name)
        if mn and vkey(ver) is not None and vkey(ver) < vkey(mn):
            found.append({"kind": "outdated", "id": "outdated", "component": c["name"], "version": ver,
                          "severity": "low", "fixed_in": mn})
    return found

def make_check(sbom_path, advisories_path=None, fail_on="high", findings_out=None):
    """Plug-in check for verify_release(extra_checks=[...])."""
    if fail_on not in SEVERITIES + ["none"]:
        raise ValueError(f"fail_on must be one of {SEVERITIES + ['none']}")
    def check(ctx):
        m = ctx["manifest"]
        if "sbom_sha256" not in m:
            raise Block("release does not commit to an SBOM (manifest has no sbom_sha256)")
        try:
            if sha256_file(sbom_path) != m["sbom_sha256"]:
                raise Block("SBOM does not match the hash in the signed manifest")
            sb = load_sbom(sbom_path)
            adv = load_advisories(advisories_path) if advisories_path else None
        except Block:
            raise
        except (ValueError, OSError) as e:
            raise Block(f"unusable SBOM or advisory file: {e}")
        main = sb["main"]
        if main["name"].lower() != m["package"].lower() or main["version"] != m["version"]:
            raise Block(f"SBOM describes {main['name']} {main['version']}, not {m['package']} {m['version']}")
        if main["sha256"] and main["sha256"] != m["sha256"]:
            raise Block("SBOM lists a different package hash than the signed manifest")
        findings = scan(sb["components"], adv) if adv else []
        if findings_out is not None:
            findings_out.extend(findings)
        bad = [f for f in findings if f["kind"] == "vulnerable" or fail_on == "low"]
        if fail_on != "none":
            worst = [f for f in bad if SEVERITIES.index(f["severity"]) >= SEVERITIES.index(fail_on)]
            if worst:
                top = max(worst, key=lambda f: SEVERITIES.index(f["severity"]))
                raise Block(f"SBOM policy: {len(worst)} finding(s) at '{fail_on}' or above, e.g. {top['id']} in "
                            f"{top['component']} {top['version']} ({top['severity']})")
        vuln = sum(f["kind"] == "vulnerable" for f in findings)
        return "SBOM verified", (f"{sb['format']}, {len(sb['components'])} components, {vuln} vulnerable, "
                                 f"{len(findings) - vuln} outdated" + ("" if adv else ", no advisories given"))
    return check
