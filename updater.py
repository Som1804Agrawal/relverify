"""Class C: update client. Rollback protection plus a safe, crash-recoverable, atomic install.

Install protocol (all under an exclusive lock):
  1 recover  : finish or discard anything a previous crash left behind (journal, temp files)
  2 verify   : every security check (signature, keys, expiry, rollback, hash, SBOM, log, TUF ...)
  3 stage    : copy to a temp file INSIDE the install folder, fsync, re-hash it
  4 journal  : write .update.journal (what we are about to install)
  5 commit   : atomic rename into place, fsync the folder, re-hash the installed file
  6 record   : write state.json atomically, then delete the journal
A crash at any point leaves either nothing installed, or a journal that the next run uses to finish step 6."""
import json, os, re, shutil, socket, tempfile, uuid
from core import (PKG_RE, Result, atomic_write, audit_event, iso, now_utc, parse_version, sha256_file,
                  verify_release)

LOCK_NAME, JOURNAL_NAME = ".update.lock", ".update.journal"


def safe_dest(install_dir, package, version):
    """Destination path that is guaranteed to be a direct child of install_dir."""
    name = f"{package}-{version}"
    root = os.path.realpath(install_dir)
    if os.path.islink(os.path.join(root, name)):
        raise ValueError("install destination is a symbolic link")
    dest = os.path.realpath(os.path.join(root, name))
    if os.path.dirname(dest) != root or os.path.basename(dest) != name:
        raise ValueError(f"unsafe install destination for {name!r}")
    return dest

def _fsync_dir(path):
    try:  # not supported on Windows; best effort
        fd = os.open(path, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError:
        pass

def check_install_dir(path):
    """The install folder is a security boundary: refuse symlinks and folders other users can write to."""
    if os.path.islink(path):
        raise ValueError("install directory is a symbolic link")
    if not os.path.isdir(path):
        raise ValueError("install directory does not exist")
    if os.name == "posix":
        st = os.stat(path)
        if st.st_uid != os.geteuid():
            raise ValueError("install directory is owned by another user")
        if st.st_mode & 0o022:
            raise ValueError("install directory is writable by other users (run: chmod go-w)")

def check_dest(dest):
    if os.path.islink(dest):
        raise ValueError("install destination is a symbolic link")
    if os.path.exists(dest) and not os.path.isfile(dest):
        raise ValueError("install destination exists and is not a regular file")


# ---- locking: the lock records who holds it, so a stale lock can be recognised safely ----
def _pid_alive(pid):
    if os.name == "nt":  # not exercised in the build environment
        import ctypes
        k = ctypes.windll.kernel32
        h = k.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
        if not h:
            return ctypes.GetLastError() == 5  # access denied: the process exists
        code = ctypes.c_ulong()
        ok = k.GetExitCodeProcess(h, ctypes.byref(code)); k.CloseHandle(h)
        return bool(ok) and code.value == 259  # STILL_ACTIVE
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except OSError:
        return True  # e.g. permission denied: the process exists
    return True

def lock_status(install_dir):
    """None if unlocked, else {'pid','host','time','token','state'} where state is held / stale / other-host / unreadable.
    'stale' only when the lock names a process on THIS machine that is provably not running. Age alone never counts."""
    path = os.path.join(install_dir, LOCK_NAME)
    if not os.path.lexists(path):
        return None
    try:
        with open(path) as f:
            info = json.load(f)
        pid, host = info["pid"], info["host"]
        if type(pid) is not int or not isinstance(host, str) or not isinstance(info.get("token"), str):
            raise ValueError
    except (OSError, ValueError, KeyError, TypeError):
        return {"state": "unreadable", "pid": None, "host": None, "time": None, "token": None}
    state = "other-host" if host != socket.gethostname() else ("held" if _pid_alive(pid) else "stale")
    return {"state": state, "pid": pid, "host": host, "time": info.get("time"), "token": info["token"]}

def break_lock(install_dir, force=False):
    """Remove a lock. Without force only a provably stale lock is removed. Returns (removed, message)."""
    st = lock_status(install_dir)
    if st is None:
        return False, "no lock present"
    if st["state"] != "stale" and not force:
        return False, (f"lock is {st['state']} (pid {st['pid']} on {st['host']}); it was NOT removed. "
                       f"If you are sure nothing is running, repeat with --force")
    os.remove(os.path.join(install_dir, LOCK_NAME))
    return True, f"removed {st['state']} lock"


class UpdateClient:
    def __init__(self, trust_path, state_path, install_dir, revocation_path=None, audit_log=None, audit_required=False, extra_checks=None):
        self.trust_path, self.state_path, self.install_dir = trust_path, state_path, install_dir
        self.revocation_path, self.audit_log, self.audit_required = revocation_path, audit_log, audit_required
        self.extra_checks = extra_checks
        if not os.path.lexists(install_dir):
            os.makedirs(install_dir, mode=0o700)

    # ---- state ----
    def _state(self):
        """Load and strictly validate state.json: {package: {version, sha256, key_id, installed_at}}.
        Old-style entries ("pkg": "1.0.0") are accepted. Anything malformed raises ValueError (fail closed)."""
        if not os.path.exists(self.state_path):
            return {}
        with open(self.state_path) as f:
            data = json.load(f)
        if not isinstance(data, dict):
            raise ValueError("state file is malformed")
        out = {}
        for pkg, v in data.items():
            if not PKG_RE.fullmatch(str(pkg)):
                raise ValueError("state file contains an invalid package name")
            e = {"version": v} if isinstance(v, str) else v
            if not isinstance(e, dict) or not isinstance(e.get("version"), str):
                raise ValueError("state file entry is malformed")
            parse_version(e["version"])
            if "sha256" in e and not (isinstance(e["sha256"], str) and re.fullmatch(r"[0-9a-f]{64}", e["sha256"])):
                raise ValueError("state file hash is malformed")
            out[pkg] = e
        return out

    def status(self):
        """Compare every recorded installation with the file on disk: ok / MISSING / MODIFIED."""
        rows = []
        for pkg, e in self._state().items():
            row = {"package": pkg, "version": e["version"], "key_id": e.get("key_id"), "installed_at": e.get("installed_at")}
            path = safe_dest(self.install_dir, pkg, e["version"])
            if not os.path.exists(path):
                row["status"] = "MISSING"
            elif os.path.islink(path):
                row["status"] = "MODIFIED"
            elif "sha256" in e and sha256_file(path) != e["sha256"]:
                row["status"] = "MODIFIED"
            else:
                row["status"] = "ok" if "sha256" in e else "ok (no recorded hash)"
            rows.append(row)
        return rows

    def installed_version(self, package):
        """Highest of: the state file, and the regular files actually present in the install folder (symlinks and
        directories are ignored). So deleting state.json does not reset rollback protection."""
        best, prefix = self._state().get(package, {}).get("version"), package + "-"
        for fn in os.listdir(self.install_dir):
            full = os.path.join(self.install_dir, fn)
            if fn.startswith(prefix) and os.path.isfile(full) and not os.path.islink(full):
                try:
                    v = fn[len(prefix):]; parse_version(v)
                except ValueError:
                    continue
                if best is None or parse_version(v) > parse_version(best):
                    best = v
        return best

    # ---- locking ----
    def _acquire(self):
        """Returns (token, None) or (None, reason). O_EXCL never follows a pre-planted symlink at the lock path."""
        path, token = os.path.join(self.install_dir, LOCK_NAME), uuid.uuid4().hex
        try:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            st = lock_status(self.install_dir) or {}
            return None, (f"another update holds the lock (state: {st.get('state')}, pid {st.get('pid')} on {st.get('host')}). "
                          f"Run 'lock-break' to check whether it is stale")
        except OSError as e:
            return None, f"cannot create lock: {e}"
        with os.fdopen(fd, "w") as f:
            json.dump({"pid": os.getpid(), "host": socket.gethostname(), "time": iso(now_utc()), "token": token}, f)
            f.flush(); os.fsync(f.fileno())
        return token, None

    def _release(self, token):
        """Only remove the lock if it is still OURS (someone may have legitimately broken and retaken it)."""
        st = lock_status(self.install_dir)
        if st and st["token"] == token:
            try:
                os.remove(os.path.join(self.install_dir, LOCK_NAME))
            except FileNotFoundError:
                pass

    # ---- crash recovery ----
    def _recover(self):
        """Run under the lock. Returns (messages, error). Finishes or discards an interrupted install."""
        msgs = []
        for fn in os.listdir(self.install_dir):  # nothing else can be staging: we hold the lock
            if fn.startswith(".tmp-") and fn.endswith(".part"):
                os.remove(os.path.join(self.install_dir, fn)); msgs.append(f"removed leftover temp file {fn}")
        jp = os.path.join(self.install_dir, JOURNAL_NAME)
        if not os.path.lexists(jp):
            return msgs, None
        try:
            with open(jp) as f:
                j = json.load(f)
            pkg, ver, sha, kid = j["package"], j["version"], j["sha256"], j["key_id"]
            if not (PKG_RE.fullmatch(pkg) and re.fullmatch(r"[0-9a-f]{64}", sha) and re.fullmatch(r"[0-9a-f]{16}", kid)):
                raise ValueError("bad field")
            parse_version(ver)
            dest = safe_dest(self.install_dir, pkg, ver)
        except (OSError, ValueError, KeyError, TypeError) as e:
            return msgs, f"update journal is corrupt ({e}); inspect {jp} and delete it if you are sure"
        if os.path.lexists(dest):
            if os.path.islink(dest) or not os.path.isfile(dest) or sha256_file(dest) != sha:
                return msgs, f"an interrupted install left {os.path.basename(dest)} in a state that does not match the journal; inspect it"
            state = self._state()
            state[pkg] = {"version": ver, "sha256": sha, "key_id": kid, "installed_at": j.get("time", iso(now_utc()))}
            atomic_write(self.state_path, json.dumps(state, indent=2))
            msgs.append(f"completed an interrupted install of {pkg} {ver}")
        else:
            msgs.append(f"discarded an interrupted update of {pkg} {ver} (nothing had been installed)")
        os.remove(jp)
        return msgs, None

    def recover(self):
        """Public entry point (CLI 'recover'): returns (ok, messages)."""
        try:
            check_install_dir(self.install_dir)
        except ValueError as e:
            return False, [str(e)]
        token, why = self._acquire()
        if why:
            return False, [why]
        try:
            msgs, err = self._recover()
            return err is None, msgs + ([err] if err else [])
        finally:
            self._release(token)

    # ---- the update itself ----
    def apply(self, pkg_path, manifest_path):
        def blocked(reason, res=None):
            res = res or Result()
            res.ok, res.reason = False, reason
            res.steps.append(("BLOCKED", reason)); return res
        try:
            check_install_dir(self.install_dir)
        except ValueError as e:
            return blocked(str(e))
        token, why = self._acquire()
        if why:
            return blocked(why)
        tmp = None
        try:
            msgs, err = self._recover()
            if err:
                return blocked(err)
            res = verify_release(pkg_path, manifest_path, self.trust_path, installed_version=self.installed_version,
                                 revocation_path=self.revocation_path, audit_log=self.audit_log,
                                 audit_required=self.audit_required, extra_checks=self.extra_checks)
            for m in msgs:
                res.steps.insert(0, ("recovered", m))
            if not res.ok:
                return res
            m = res.manifest
            try:
                dest = safe_dest(self.install_dir, m["package"], m["version"]); check_dest(dest)
            except ValueError as e:
                return blocked(str(e), res)
            try:
                # 3. stage: temp file in the same folder, synced and re-hashed (guards against the package changing after verification)
                fd, tmp = tempfile.mkstemp(dir=self.install_dir, prefix=".tmp-", suffix=".part")
                with os.fdopen(fd, "wb") as out, open(pkg_path, "rb") as src:
                    shutil.copyfileobj(src, out); out.flush(); os.fsync(out.fileno())
                if sha256_file(tmp) != m["sha256"]:
                    return blocked("package changed during install", res)
                # 4. journal what we are about to do, so a crash after the rename can be finished by the next run
                jp = os.path.join(self.install_dir, JOURNAL_NAME)
                atomic_write(jp, json.dumps({"package": m["package"], "version": m["version"], "sha256": m["sha256"],
                                             "key_id": m["key_id"], "time": iso(now_utc())}))
                # 5. commit
                os.replace(tmp, dest); tmp = None
                _fsync_dir(self.install_dir)
                if os.path.islink(dest) or sha256_file(dest) != m["sha256"]:  # post-install check against a race
                    os.remove(dest); os.remove(jp)
                    return blocked("installed file changed immediately after install; it was removed", res)
                # 6. record
                state = self._state()
                state[m["package"]] = {"version": m["version"], "sha256": m["sha256"], "key_id": m["key_id"],
                                       "installed_at": iso(now_utc())}
                atomic_write(self.state_path, json.dumps(state, indent=2))
                os.remove(jp)
            except OSError as e:
                audit_event(self.audit_log, "install-failed", package=m["package"], version=m["version"], reason=str(e)[:120])
                return blocked(f"install failed: {e}", res)
            audit_event(self.audit_log, "installed", package=m["package"], version=m["version"], sha256=m["sha256"])
            res.steps.append(("installed", dest))
            return res
        finally:
            if tmp and os.path.exists(tmp):
                os.remove(tmp)
            self._release(token)
