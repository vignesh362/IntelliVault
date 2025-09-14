#!/usr/bin/env python3
# Security/ContextAuth/ui/popup_pwd.py
from __future__ import annotations
import os, sys, json, time, hashlib, argparse
from pathlib import Path
import tkinter as tk
from tkinter import messagebox
import numpy as np

# Your keystroke scorer (unchanged import path)
from ...Keystroke.adapter import score_sample

# Paths
BASE = Path(__file__).resolve().parents[2]  # .../Security
PWD_JSON = BASE / "Keystroke" / "store" / "password.json"
BASELINE = BASE / "Keystroke" / "store" / "baseline.npz"

PRINTABLE = set(chr(i) for i in range(32, 127))
MOD_KEYS = {"Shift_L","Shift_R","Control_L","Control_R","Command","Option_L","Option_R","Alt_L","Alt_R"}

def _verify_password(pw: str) -> bool:
    if not PWD_JSON.exists():
        return False
    obj = json.loads(PWD_JSON.read_text(encoding="utf-8"))
    salt = bytes.fromhex(obj["salt_hex"])
    iters = int(obj.get("iters", 200_000))
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), salt, iters, dklen=32)
    return dk.hex() == obj["pbkdf2_hex"]

def _baseline_len() -> int | None:
    try:
        data = np.load(BASELINE)
        return int(data["length"][0])
    except Exception:
        return None

class PasswordPopup:
    def __init__(self, root, keystroke_thr: float = 0.000001, bypass_keystroke: bool = False):
        self.root = root
        self.keystroke_thr = keystroke_thr
        self.bypass = bypass_keystroke
        self.result = {"flag":"deny","reason":"closed"}

        root.title("IntelliVault — Password & Keystroke Check")
        root.geometry("640x280+240+160")
        root.update_idletasks()
        root.lift()
        try:
            root.attributes("-topmost", True)
            root.after(250, lambda: root.attributes("-topmost", False))
        except tk.TclError:
            pass

        tk.Label(root, text="Enter your password:", font=("Helvetica", 12, "bold")).pack(anchor="w", padx=14, pady=(12,4))
        self.entry = tk.Entry(root, show="*", font=("Helvetica", 16))
        self.entry.pack(fill="x", padx=14)
        self.entry.focus_set()

        self.status = tk.StringVar(value="We’ll verify the password and your typing pattern. Avoid backspace/paste.")
        tk.Label(root, textvariable=self.status, fg="gray").pack(anchor="w", padx=14, pady=(8,6))

        row = tk.Frame(root); row.pack(fill="x", padx=14)
        tk.Button(row, text="Submit", command=self.on_submit).pack(side="left")
        tk.Button(row, text="Cancel", command=self._on_close).pack(side="right")

        # capture state
        self.down_queue: list[float] = []
        self.last_up_t: float | None = None
        self.dwell: list[float] = []
        self.flight: list[float] = []

        # bindings
        self.entry.bind("<KeyPress>", self.on_key_down)
        self.entry.bind("<KeyRelease>", self.on_key_up)
        self.entry.bind("<Return>", lambda e: self.on_submit())
        self.entry.bind("<Control-v>", self.on_paste_attempt)
        self.entry.bind("<Command-v>", self.on_paste_attempt)
        self.entry.bind("<FocusOut>", lambda e: self._soft_reset("Focus changed. Retype."))

    # helpers
    def _soft_reset(self, msg: str | None = None):
        self.down_queue.clear()
        self.last_up_t = None
        self.dwell.clear()
        self.flight.clear()
        if msg:
            self.status.set(msg)

    def on_paste_attempt(self, _):
        self.entry.delete(0, "end")
        self._soft_reset("Paste blocked. Please type the password.")
        return "break"

    # events
    def on_key_down(self, e):
        if e.keysym in ("BackSpace", "Delete"):
            self.entry.delete(0, "end")
            self._soft_reset("Backspace/Delete used. Retype.")
            return "break"
        if e.keysym in MOD_KEYS or not e.char or e.char not in PRINTABLE:
            return
        self.down_queue.append(time.perf_counter())

    def on_key_up(self, e):
        if e.keysym in MOD_KEYS or not e.char or e.char not in PRINTABLE:
            return
        if not self.down_queue:
            self.entry.delete(0, "end")
            self._soft_reset("Capture desynced. Please retype.")
            return
        t_up = time.perf_counter()
        t_down = self.down_queue.pop(0)
        self.dwell.append(t_up - t_down)
        if self.last_up_t is not None:
            self.flight.append(t_down - self.last_up_t)
        self.last_up_t = t_up

    def _finalize_and_exit(self, res: dict):
        """Print JSON and exit with proper code for subprocess usage."""
        self.result = res
        print(json.dumps(res, indent=2), flush=True)
        code = 0 if res.get("flag") == "allow" else 1
        self.root.after(80, lambda: sys.exit(code))

    def _deny(self, reason: str, msgbox_title="Denied", msgbox_text="Access denied."):
        self.status.set(reason.replace("-", " ").capitalize() + ".")
        messagebox.showerror(msgbox_title, msgbox_text)
        self._finalize_and_exit({"flag":"deny","reason":reason})

    def on_submit(self):
        pw = self.entry.get()

        # 1) password text
        if not _verify_password(pw):
            return self._deny("password", "Denied", "Password incorrect.")

        # 2) baseline + length
        L = _baseline_len()
        if L is None:
            return self._deny("keystroke-missing", "Denied", "Baseline missing or invalid. Please enroll first.")
        if len(pw) != L:
            message = f"Password length {len(pw)} != enrolled {L}. Re-enroll or use the enrolled password."
            self.status.set(f"Password length differs from enrolled length {L}.")
            messagebox.showerror("Denied", message)
            return self._finalize_and_exit({"flag":"deny","reason":"length-mismatch"})

        # 3) full capture?
        if len(self.dwell) != L or len(self.flight) != L - 1:
            self.status.set("Incomplete capture: please retype slowly and avoid backspace.")
            messagebox.showwarning("Try again", "We didn't capture a full keystroke sample. Please retype carefully.")
            self.entry.delete(0, "end")
            self._soft_reset("Start typing again (no backspace/paste).")
            return

        # 4) score
        try:
            ks = score_sample(self.dwell, self.flight)  # higher is better (your adapter decides)
        except Exception as e:
            self.status.set(f"Keystroke error: {e}")
            messagebox.showerror("Denied", "Keystroke scoring failed. Check baseline.")
            return self._finalize_and_exit({"flag":"deny","reason":"keystroke-error"})

        # BYPASS (optional) — env or CLI flag
        if self.bypass or os.getenv("INTELLIVAULT_KS_BYPASS") == "1":
            self.status.set(f"Password + Keystroke OK (score={ks:.3f}) [BYPASSED]")
            messagebox.showinfo("Verified", "Password accepted.")
            return self._finalize_and_exit({"flag":"allow","score":round(float(ks),3),"bypass":True})

        # Threshold check (default 0.08)
        if float(ks) >= float(self.keystroke_thr):
            self.status.set(f"Password + Keystroke OK (score={ks:.3f})")
            messagebox.showinfo("Verified", "You now have access.")
            return self._finalize_and_exit({"flag":"allow","score":round(float(ks),3)})
        else:
            self.status.set(f"Keystroke score too low (score={ks:.3f} < thr={self.keystroke_thr}).")
            messagebox.showerror("Denied", "Your typing pattern did not match closely enough.")
            return self._finalize_and_exit({"flag":"deny","reason":"keystroke-low","score":round(float(ks),3)})

    def _on_close(self):
        self._finalize_and_exit({"flag":"deny","reason":"closed"})

def run_password_keystroke_popup(keystroke_thr: float = 0.08, bypass_keystroke: bool = False) -> bool:
    root = tk.Tk()
    app = PasswordPopup(root, keystroke_thr=keystroke_thr, bypass_keystroke=bypass_keystroke)
    root.mainloop()
    res = getattr(app, "result", {"flag":"deny"})
    return res.get("flag") == "allow"

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--thr", type=float, default=float(os.getenv("INTELLIVAULT_KS_THR", "0.08")),
                    help="Keystroke score threshold (>= passes).")
    ap.add_argument("--bypass", action="store_true", help="Bypass keystroke threshold (always allow if password ok).")
    args = ap.parse_args()

    root = tk.Tk()
    app = PasswordPopup(root, keystroke_thr=args.thr, bypass_keystroke=args.bypass)
    root.mainloop()

if __name__ == "__main__":
    main()
