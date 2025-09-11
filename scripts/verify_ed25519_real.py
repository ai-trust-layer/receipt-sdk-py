import json, base64, sys
from nacl.signing import VerifyKey

SUBSET_KEYS = ["id","issued_at","input_hash","output_hash","model_version","policy_version"]

def canonicalize_subset(r):
    obj = {k: r[k] for k in SUBSET_KEYS}
    return json.dumps(obj, separators=(',', ':'), ensure_ascii=False)

def verify_receipt(path):
    with open(path, 'r', encoding='utf-8') as f:
        r = json.load(f)
    sig = r.get('signature')
    if not sig:
        print("signature: FAIL"); print("reason: not_provided"); sys.exit(1)
    if str(sig.get('alg','')).lower() != 'ed25519':
        print("signature: FAIL"); print("reason: alg_unsupported"); sys.exit(1)
    kid = sig.get('kid','')
    if not kid.startswith('ed25519:'):
        print("signature: FAIL"); print("reason: kid_format"); sys.exit(1)
    pub_hex = kid.split(':',1)[1]
    msg = canonicalize_subset(r).encode('utf-8')
    sig_bytes = base64.b64decode(sig.get('sig',''))
    try:
        VerifyKey(bytes.fromhex(pub_hex)).verify(msg, sig_bytes)
        print("signature: PASS")
    except Exception:
        print("signature: FAIL"); print("reason: bad_signature"); sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: python scripts/verify_ed25519_real.py <receipt.json>")
        sys.exit(2)
    verify_receipt(sys.argv[1])
