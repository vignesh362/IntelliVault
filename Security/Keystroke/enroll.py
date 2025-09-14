from __future__ import annotations
import json, os, time, hashlib
from dataclasses import dataclass
from pathlib import Path
import tkinter as tk
from tkinter import messagebox
import numpy as np

STORE = Path(__file__).resolve().parent / "store"
STORE.mkdir(parents=True, exist_ok=True)
BASELINE = STORE / "baseline.npz"
PWD_JSON = STORE / "password.json"

PBKDF2_ITERS = 200_000

def _pbkdf2_hash(password: str, salt: bytes | None = None):
    salt = salt or os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERS, dklen=32)
    return salt, dk

def _save_password_hash(password: str):
    salt, dk = _pbkdf2_hash(password)
    PWD_JSON.write_text(json.dumps({
        "salt_hex": salt.hex(),
        "pbkdf2_hex": dk.hex(),
        "iters": PBKDF2_ITERS
    }, indent=2), encoding="utf-8")
    os.chmod(PWD_JSON, 0o600)

@dataclass
class Sample:
    dwell: list[float]
    flight: list[float]

class EnrollApp:
    def __init__(self, root, target_samples=5):
        self.root = root
        self.target = target_samples
        self.samples: list[Sample] = []
        self.key_down_times = {}
        self.last_key_up_t = None
        self.password = tk.StringVar()

        root.title("IntelliVault — Keystroke Enrollment")
        root.geometry("640x360")

        # Top password field (BOUND to self.password)
        tk.Label(root, text="Set a password (will be hashed & stored locally):", font=("Helvetica", 12, "bold")).pack(anchor="w", padx=12, pady=(12,4))
        self.entry_pw = tk.Entry(root, textvariable=self.password, show="*", font=("Helvetica", 14))
        self.entry_pw.pack(fill="x", padx=12)
        self.entry_pw.focus_set()

        # Instructions
        tk.Label(root, text="Type the EXACT password below when asked.\nWe will record timings for multiple samples.", fg="gray").pack(anchor="w", padx=12, pady=(8,8))

        # Prompt + typing box (disabled until Start Sample)
        self.sample_prompt = tk.Label(root, text="Click 'Start Sample' to begin", font=("Helvetica", 11, "bold"))
        self.sample_prompt.pack(anchor="w", padx=12)

        self.entry_type = tk.Entry(root, show="*", font=("Helvetica", 16), state="disabled")
        self.entry_type.pack(fill="x", padx=12, pady=(8,0))

        # Buttons
        btns = tk.Frame(root); btns.pack(pady=12)
        tk.Button(btns, text="Start Sample", command=self.start_sample).pack(side="left", padx=6)
        tk.Button(btns, text="Finish Enrollment", command=self.finish).pack(side="left", padx=6)

        # Status
        self.status = tk.StringVar(value=f"Collected: 0 / {self.target}")
        tk.Label(root, textvariable=self.status).pack(anchor="w", padx=12)

        # Bindings for typing capture
        self.entry_type.bind("<KeyPress>", self.on_key_down)
        self.entry_type.bind("<KeyRelease>", self.on_key_up)
        self.entry_type.bind("<Return>", lambda e: self.capture_sample())
        # block paste
        self.entry_type.bind("<Control-v>", self._block_paste)
        self.entry_type.bind("<Command-v>", self._block_paste)

        # capture buffers
        self.current_chars = []
        self.dwell = []
        self.flight = []

    def _block_paste(self, _):
        self.entry_type.delete(0, "end")
        self._reset_capture("Paste blocked. Please type the password.")
        return "break"

    def _reset_capture(self, msg=None):
        self.key_down_times.clear()
        self.last_key_up_t = None
        self.current_chars = []
        self.dwell = []
        self.flight = []
        if msg: self.sample_prompt.config(text=msg)

    def start_sample(self):
        pw = self.password.get()
        if len(pw) < 4:
            messagebox.showwarning("Short password", "Please enter a password of at least 4 characters.")
            return
        self.sample_prompt.config(text=f"Type password EXACTLY:   {pw}")
        self.entry_type.configure(state="normal")
        self.entry_type.delete(0, "end")
        self._reset_capture()
        self.entry_type.focus_set()

    def on_key_down(self, e):
        if e.keysym in ("BackSpace", "Delete"):
            self.entry_type.delete(0, "end")
            self._reset_capture("Backspace/Delete used. Start typing again.")
            return "break"
        if len(e.char) == 1:
            idx = len(self.dwell)
            self.key_down_times[idx] = time.perf_counter()

    def on_key_up(self, e):
        if len(e.char) == 1:
            t_up = time.perf_counter()
            idx = len(self.dwell)
            t_down = self.key_down_times.get(idx)
            if t_down is None:
                self.entry_type.delete(0, "end")
                self._reset_capture("Capture desynced. Please retype.")
                return
            self.dwell.append(t_up - t_down)
            if self.last_key_up_t is not None:
                self.flight.append(t_down - self.last_key_up_t)
            self.last_key_up_t = t_up

    def capture_sample(self):
        pw = self.password.get()
        typed = self.entry_type.get()
        if typed != pw:
            messagebox.showerror("Mismatch", "Typed password does not match. Try again.")
            return
        if len(self.dwell) != len(pw) or len(self.flight) != len(pw)-1:
            messagebox.showerror("Incomplete", "Timing capture incomplete. Try again.")
            return
        self.samples.append(Sample(self.dwell[:], self.flight[:]))
        self.status.set(f"Collected: {len(self.samples)} / {self.target}")
        self.entry_type.configure(state="disabled")
        if len(self.samples) >= self.target:
            messagebox.showinfo("Done", "Required samples collected. Click 'Finish Enrollment' to save.")

    def finish(self):
        if len(self.samples) == 0:
            messagebox.showwarning("No samples", "Collect at least one sample.")
            return
        pw = self.password.get()
        L = len(pw)
        dw = np.array([s.dwell for s in self.samples])     # (N, L)
        fl = np.array([s.flight for s in self.samples])    # (N, L-1)

        dwell_mean = dw.mean(axis=0)
        dwell_std  = np.clip(dw.std(axis=0), 1e-6, None)
        flight_mean = fl.mean(axis=0)
        flight_std  = np.clip(fl.std(axis=0), 1e-6, None)

        np.savez_compressed(
            BASELINE,
            dwell_mean=dwell_mean.astype("float32"),
            dwell_std=dwell_std.astype("float32"),
            flight_mean=flight_mean.astype("float32"),
            flight_std=flight_std.astype("float32"),
            length=np.array([L], dtype="int32"),
        )
        os.chmod(BASELINE, 0o600)

        _save_password_hash(pw)

        messagebox.showinfo("Saved", f"Baseline + password saved to {STORE}")
        self.root.quit()

def main():
    root = tk.Tk()
    app = EnrollApp(root, target_samples=5)
    root.mainloop()

if __name__ == "__main__":
    main()
