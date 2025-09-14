#!/usr/bin/env python3
# Security/ContextAuth/ui/popup.py
import sys, json, random, argparse
import tkinter as tk
from tkinter import messagebox

_RANDOM_QUESTIONS = [
    "What color is your favorite umbrella?",
    "How many windows are in your living room?",
    "What’s the last movie you watched?",
    "Do you prefer sunrise or sunset?",
    "Cats or dogs?",
    "Pick a random number between 1 and 7.",
    "Name a city you want to visit.",
]

def _verify_context(text: str, min_chars: int) -> dict:
    ok = len(text.strip()) >= min_chars
    return {"status":"OK","flag":"allow" if ok else "deny","reason":"pass" if ok else "min-chars"}

class PopupApp:
    def __init__(self, root, min_chars: int):
        self.root = root
        self.min_chars = min_chars
        self.result = {"status":"FAIL","flag":"deny","reason":"closed"}

        root.title("IntelliVault — Context Check")
        root.geometry("720x420+200+120")
        root.update_idletasks()
        root.lift()
        try:
            root.attributes("-topmost", True)
            root.after(250, lambda: root.attributes("-topmost", False))
        except tk.TclError:
            pass

        tk.Label(root, text="Random Prompt (ignore this):", font=("Helvetica", 12, "bold")).pack(anchor="w", padx=12, pady=(12,4))
        self.qv = tk.StringVar()
        self._new_prompt()
        tk.Message(root, textvariable=self.qv, width=680, justify="left").pack(anchor="w", padx=12)

        row = tk.Frame(root); row.pack(anchor="w", padx=12, pady=(6, 0))
        tk.Button(row, text="New Prompt", command=self._new_prompt).pack(side="left")

        tk.Label(root, text="Your typed statement (used for context verification):", font=("Helvetica", 12, "bold")).pack(anchor="w", padx=12, pady=(16,4))
        self.text = tk.Text(root, height=8, wrap="word"); self.text.pack(fill="both", expand=True, padx=12)
        self.text.focus_set()

        tk.Button(root, text="Submit", command=self.on_submit).pack(pady=10)
        self.status = tk.StringVar(value=f"Type at least {self.min_chars} characters related to your private context.")
        tk.Label(root, textvariable=self.status, fg="gray").pack(anchor="w", padx=12, pady=(0,8))

        root.bind("<Return>", lambda e: self.on_submit())
        root.protocol("WM_DELETE_WINDOW", self._on_close)

    def _new_prompt(self):
        self.qv.set(random.choice(_RANDOM_QUESTIONS))

    def _on_close(self):
        self.root.quit()

    def on_submit(self):
        content = self.text.get("1.0", "end").strip()
        res = _verify_context(content, self.min_chars)
        self.result = res
        print(json.dumps(res, indent=2), flush=True)
        code = 0 if res.get("flag") == "allow" else 1
        self.root.after(100, lambda: sys.exit(code))

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--min-chars", type=int, default=12)
    args = ap.parse_args()

    root = tk.Tk()
    app = PopupApp(root, min_chars=args.min_chars)
    root.mainloop()

if __name__ == "__main__":
    main()
