import sys, json, base64
from nacl.signing import VerifyKey
from nacl.exceptions import BadSignatureError
from common_canonical import canonicalize_subset_bytes

def verify_signature(receipt: dict):
    s = receipt.get("signature")
    if not s: return False, "not_provided"
    if s.get("alg")!="ed25519" or not s.get("sig") or not str(s.get("kid","")).startswith("ed25519:"):
        return False, "unsupported_alg"
    pub_hex = s["kid"].split(":",1)[1]
    pub = VerifyKey(bytes.fromhex(pub_hex))
    sig = base64.b64decode(s["sig"])
    msg = canonicalize_subset_bytes(receipt)
    try:
        pub.verify(msg, sig)
        return True, "Signature valid"
    except BadSignatureError:
        return False, "bad_signature"

if __name__ == "__main__":
    p = sys.argv[1]
    with open(p,"r",encoding="utf-8") as f: r = json.load(f)
    ok, reason = verify_signature(r)
    print(f"signature: {'PASS' if ok else 'FAIL'} ({reason})")
    sys.exit(0 if ok else 1)
