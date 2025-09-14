#!/usr/bin/env python3
# Security/ContextAuth/authorize.py
"""
Runs the combined authorization flow as modules:
1) Context prompt  -> Security.ContextAuth.ui.popup
2) Pwd+Keystroke   -> Security.ContextAuth.ui.popup_pwd

Prints a single JSON result and exits:
- 0 on success (both allowed)
- 1 on failure
"""
from __future__ import annotations
import sys, json, shlex, subprocess
from typing import Optional, Tuple, Dict, Any

def _run_module(modname: str, args: Optional[str] = None, timeout: Optional[int] = None) -> Tuple[int, str, str]:
    exe = shlex.quote(sys.executable)
    mod = shlex.quote(modname)
    cmd = f"{exe} -m {mod}"
    if args:
        cmd += f" {args}"
    proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
    return proc.returncode, (proc.stdout or "").strip(), (proc.stderr or "").strip()

def _parse_json_or_exitcode(stdout: str, returncode: int, default_reason: str) -> Dict[str, Any]:
    try:
        data = json.loads(stdout) if stdout else {}
        if not isinstance(data, dict):
            data = {}
    except Exception:
        data = {}

    # Harmonize with returncode if no/invalid JSON
    if returncode == 0:
        data.setdefault("flag", "allow")
        data.setdefault("reason", "ok")
    else:
        data.setdefault("flag", "deny")
        data.setdefault("reason", default_reason if not stdout else "stdout-not-json")
        if stdout and "stdout" not in data:
            data["stdout"] = stdout[:200]
    return data

def authorize(min_chars: int = 12, timeout_each: Optional[int] = None) -> Dict[str, Any]:
    # Step 1: Context
    code1, out1, err1 = _run_module("Security.ContextAuth.ui.popup", args=f"--min-chars {min_chars}", timeout=timeout_each)
    res1 = _parse_json_or_exitcode(out1, code1, "context-deny")
    if code1 != 0 or res1.get("flag") != "allow":
        return {
            "status": "FAIL",
            "stage": "context",
            "flag": "deny",
            "reason": res1.get("reason","context-deny"),
            "detail": {"stdout": out1, "stderr": err1, "code": code1}
        }

    # Step 2: Password + Keystroke
    code2, out2, err2 = _run_module("Security.ContextAuth.ui.popup_pwd", timeout=timeout_each)
    res2 = _parse_json_or_exitcode(out2, code2, "password-deny")
    if code2 != 0 or res2.get("flag") != "allow":
        return {
            "status": "FAIL",
            "stage": "password-keystroke",
            "flag": "deny",
            "reason": res2.get("reason","password-deny"),
            "detail": {"stdout": out2, "stderr": err2, "code": code2}
        }

    return {
        "status": "OK",
        "flag": "allow",
        "reason": "both-pass",
        "context_result": res1,
        "password_result": res2
    }

def main():
    result = authorize(min_chars=12, timeout_each=None)
    print(json.dumps(result, indent=2), flush=True)
    sys.exit(0 if (result.get("flag") == "allow") else 1)

if __name__ == "__main__":
    main()
