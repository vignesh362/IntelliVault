import sys, json
from pathlib import Path
from ..context.context_manager import set_context
from ..verify.verify import verify_answer

BASE = Path(__file__).resolve().parents[1]
ASSETS = BASE / "assets"   # kept for future, not needed by current API

USAGE = 'Usage: python -m Security.ContextAuth.scripts.smoke_flow SET|VERIFY|ROTATE "text..."'

def main():
    if len(sys.argv) < 3:
        print(USAGE)
        sys.exit(2)

    cmd = sys.argv[1].upper()
    text = " ".join(sys.argv[2:])

    if cmd in ("SET", "ROTATE"):
        # builds context bank + background bank and persists them
        res = set_context(text)
        print(json.dumps(res, indent=2))
        sys.exit(0)

    elif cmd == "VERIFY":
        res = verify_answer(text)
        print(json.dumps(res, indent=2))
        # exit 0 on allow, 1 on deny (for your friend's integration)
        sys.exit(0 if res.get("flag") == "allow" else 1)

    else:
        print("Unknown cmd. " + USAGE)
        sys.exit(2)

if __name__ == "__main__":
    main()
