import sys, json, base64, os
from nacl.signing import SigningKey
from common_canonical import canonicalize_subset_bytes

# cheie demo deterministă (NU pt. producție)
SEED = bytes([1]*32)

def main(out_path):
    sk = SigningKey(SEED)
    vk = sk.verify_key
    r = {
        "id":"rec_py_interop",
        "issued_at":"2025-09-10T12:00:00Z",
        "input_hash":"a"*64,
        "output_hash":"b"*64,
        "model_version":"gpt-x-2025-09-01",
        "policy_version":"policy-v1.0",
    }
    msg = canonicalize_subset_bytes(r)
    sig = sk.sign(msg).signature
    r["signature"] = {
        "alg":"ed25519",
        "kid":"ed25519:"+vk.encode().hex(),
        "sig":base64.b64encode(sig).decode("ascii"),
    }
    with open(out_path,"w",encoding="utf-8") as f:
        json.dump(r,f,ensure_ascii=False,separators=(',',':'))

if __name__ == "__main__":
    out = sys.argv[1]
    main(out)
    print(f"Wrote {out}")
