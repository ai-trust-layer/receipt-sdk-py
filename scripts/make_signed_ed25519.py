import json, base64, sys
from nacl.signing import SigningKey

SUBSET_KEYS = ["id","issued_at","input_hash","output_hash","model_version","policy_version"]

def canonicalize_subset(r):
    obj = {k: r[k] for k in SUBSET_KEYS}
    return json.dumps(obj, separators=(',', ':'), ensure_ascii=False)

r = {
  "id": "rec_py_001",
  "issued_at": "2025-09-10T12:00:00Z",
  "input_hash": "a"*64,
  "output_hash": "b"*64,
  "model_version": "gpt-x-2025-09-01",
  "policy_version": "policy-v1.0"
}

sk = SigningKey(b"\x01"*32)
vk = sk.verify_key
msg = canonicalize_subset(r).encode('utf-8')
sig = sk.sign(msg).signature
r["signature"] = {
  "alg": "ed25519",
  "kid": "ed25519:" + vk.encode().hex(),
  "sig": base64.b64encode(sig).decode('ascii')
}

if __name__ == "__main__":
    if len(sys.argv) == 2:
        with open(sys.argv[1], "w", encoding="utf-8") as f:
            json.dump(r, f, ensure_ascii=False)
    else:
        sys.stdout.write(json.dumps(r, ensure_ascii=False))
