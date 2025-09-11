import sys, json
from .signature import verify_signature

def main():
    if len(sys.argv) < 2:
        print("Usage: python -m receipt_verify <receipt.json>", file=sys.stderr)
        sys.exit(2)
    path = sys.argv[1]
    with open(path, "r", encoding="utf-8") as f:
        r = json.load(f)
    if "signature" not in r:
        print("signature: not present")
        sys.exit(0)
    res = verify_signature(r)
    if res.get("ok"):
        print("signature: PASS")
    else:
        print(f"signature: FAIL ({res.get('reason','unknown')})")
    sys.exit(0)
