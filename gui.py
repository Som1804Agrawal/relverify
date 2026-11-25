"""Class B: desktop verifier (Tkinter): checklist, package details, copy buttons, report export,
publisher trust records with search and confirmed revoke, and a trust-on-first-use prompt."""
import json, os
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from core import TrustStore, format_report, verify_release

CONFIG = os.path.join(os.path.expanduser("~"), ".relverify_gui.json")  # remembers the last paths
FIELDS = (("pkg", "Package"), ("manifest", "Manifest"), ("trust", "Trust store"), ("crl", "Revocation list (optional)"))
INFO = (("package", "Package"), ("version", "Version"), ("publisher", "Publisher"), ("alg", "Algorithm"),
        ("key_id", "Key ID"), ("sha256", "SHA-256"))


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Release Verifier")
        self.last = None  # (Result, package path) of the latest verification
        self.vars = {k: tk.StringVar() for k, _ in FIELDS}
        self.info = {k: tk.StringVar(value="-") for k, _ in INFO}
        self.filter = tk.StringVar()
        self.filter.trace_add("write", lambda *_: self.refresh())
        self._load_config()

        top = ttk.Frame(self, padding=8); top.grid(row=0, column=0, sticky="ew")
        for i, (k, label) in enumerate(FIELDS):
            ttk.Label(top, text=label).grid(row=i, column=0, sticky="w", pady=2)
            ttk.Entry(top, textvariable=self.vars[k], width=60).grid(row=i, column=1, padx=6)
            ttk.Button(top, text="Browse", command=lambda k=k: self.browse(k)).grid(row=i, column=2)
        buttons = ttk.Frame(top); buttons.grid(row=len(FIELDS), column=0, columnspan=3, pady=6)
        ttk.Button(buttons, text="Verify", command=self.verify).pack(side="left", padx=4)
        self.export_btn = ttk.Button(buttons, text="Export report", command=self.export, state="disabled")
        self.export_btn.pack(side="left", padx=4)
        self.progress = ttk.Progressbar(top, mode="indeterminate")
        self.progress.grid(row=len(FIELDS) + 1, column=0, columnspan=3, sticky="ew")

        self.status = tk.Label(self, text="Choose the files and click Verify", font=("TkDefaultFont", 16, "bold"), pady=8)
        self.status.grid(row=1, column=0, sticky="ew")

        mid = ttk.Frame(self, padding=8); mid.grid(row=2, column=0, sticky="ew")
        self.log = tk.Text(mid, height=9, width=60, state="disabled")
        self.log.tag_configure("pass", foreground="#1a7f37"); self.log.tag_configure("fail", foreground="#cf222e")
        self.log.grid(row=0, column=0, sticky="nw")
        details = ttk.LabelFrame(mid, text="Package details", padding=6); details.grid(row=0, column=1, padx=10, sticky="n")
        for i, (k, label) in enumerate(INFO):
            ttk.Label(details, text=label).grid(row=i, column=0, sticky="w")
            ttk.Entry(details, textvariable=self.info[k], width=36, state="readonly").grid(row=i, column=1, padx=4, pady=1)
            if k in ("key_id", "sha256"):
                ttk.Button(details, text="Copy", width=6, command=lambda k=k: self.copy(self.info[k].get())).grid(row=i, column=2)

        trust = ttk.LabelFrame(self, text="Publisher trust records", padding=6); trust.grid(row=3, column=0, sticky="ew", padx=8, pady=8)
        bar = ttk.Frame(trust); bar.grid(row=0, column=0, sticky="ew")
        ttk.Label(bar, text="Search").pack(side="left")
        ttk.Entry(bar, textvariable=self.filter, width=24).pack(side="left", padx=6)
        ttk.Button(bar, text="Refresh", command=self.refresh).pack(side="left")
        ttk.Button(bar, text="Revoke selected", command=self.revoke).pack(side="left", padx=6)
        cols = ("name", "key_id", "fingerprint", "not_before", "not_after", "status")
        self.tree = ttk.Treeview(trust, columns=cols, show="headings", height=5)
        for c, w in zip(cols, (110, 120, 440, 90, 90, 80)):
            self.tree.heading(c, text=c); self.tree.column(c, width=w)
        self.tree.grid(row=1, column=0, pady=4)
        self.refresh()

    # ---- helpers ----
    def _load_config(self):
        try:
            with open(CONFIG) as f:
                for k, v in json.load(f).items():
                    if k in self.vars:
                        self.vars[k].set(v)
        except (OSError, ValueError, AttributeError):
            pass

    def _save_config(self):
        try:
            with open(CONFIG, "w") as f:
                json.dump({k: v.get() for k, v in self.vars.items()}, f)
        except OSError:
            pass

    def browse(self, key):
        path = filedialog.askopenfilename()
        if path:
            self.vars[key].set(path)
            if key == "trust":
                self.refresh()

    def copy(self, text):
        self.clipboard_clear(); self.clipboard_append(text)

    def tofu(self, publisher, key_id, fingerprint):
        return messagebox.askyesno("Unknown publisher", f"Publisher: {publisher}\nKey ID: {key_id}\n"
                                   f"Fingerprint:\n{fingerprint}\n\nCompare this fingerprint with the publisher's "
                                   f"website or another trusted channel. Trust this key?")

    # ---- actions ----
    def verify(self):
        v = {k: x.get().strip() for k, x in self.vars.items()}
        self.progress.start(10); self.update_idletasks()
        try:
            res = verify_release(v["pkg"], v["manifest"], v["trust"], tofu=self.tofu, revocation_path=v["crl"] or None)
        except Exception as e:  # never leave the user without an answer; an error counts as blocked
            self.progress.stop(); messagebox.showerror("Verification error", str(e)); return
        self.progress.stop()
        self.last = (res, v["pkg"]); self.export_btn.config(state="normal"); self._save_config()
        self.status.config(text="VERIFIED: safe to install" if res.ok else "BLOCKED: " + res.reason,
                           fg="#1a7f37" if res.ok else "#cf222e")
        self.log.config(state="normal"); self.log.delete("1.0", "end")
        for name, detail in res.steps:
            failed = name == "BLOCKED"
            self.log.insert("end", f"{'✗' if failed else '✓'} {name}" + (f": {detail}" if detail != "ok" else "") + "\n",
                            "fail" if failed else "pass")
        self.log.config(state="disabled")
        m = dict(res.manifest, alg=res.alg or "-")
        for k, _ in INFO:
            self.info[k].set(m.get(k, "-"))
        self.refresh()

    def export(self):
        if not self.last:
            return
        path = filedialog.asksaveasfilename(defaultextension=".txt", initialfile="verification-report.txt")
        if path:
            with open(path, "w") as f:
                f.write(format_report(*self.last))

    def refresh(self):
        self.tree.delete(*self.tree.get_children())
        path, needle = self.vars["trust"].get().strip(), self.filter.get().strip().lower()
        if not path or not os.path.exists(path):
            return
        try:
            records = TrustStore(path).records.values()
        except Exception as e:
            self.status.config(text=f"Trust store problem: {e}", fg="#cf222e"); return
        for r in records:
            if needle and needle not in (r["name"] + r["key_id"]).lower():
                continue
            self.tree.insert("", "end", iid=r["key_id"], values=(
                r["name"], r["key_id"], r["fingerprint"], r["not_before"][:10], r["not_after"][:10],
                "REVOKED" if r["revoked"] else "active"))

    def revoke(self):
        selected = self.tree.selection()
        if not selected:
            return
        if not messagebox.askyesno("Revoke key", f"Revoke {len(selected)} key(s)? Everything they signed will be blocked."):
            return
        store = TrustStore(self.vars["trust"].get())
        for key_id in selected:
            store.revoke(key_id)
        self.refresh()


def run():
    App().mainloop()


if __name__ == "__main__":
    run()
