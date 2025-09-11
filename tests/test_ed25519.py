import base64
from nacl.signing import SigningKey
from receipt_verify.signature import canonicalize_subset, verify_signature

PRIV_HEX = "01"*32

def make_base():
    return {
        "id":"rec_py_001",
        "issued_at":"2025-09-10T12:00:00Z",
        "input_hash":"a"*64,
        "output_hash":"b"*64,
        "model_version":"gpt-x-2025-09-01",
        "policy_version":"policy-v1.0"
    }

def sign(r):
    sk = SigningKey(bytes.fromhex(PRIV_HEX))
    vk = sk.verify_key
    msg = canonicalize_subset(r).encode("utf-8")
    sig = sk.sign(msg).signature
    r["signature"] = {"alg":"ed25519","kid":"ed25519:"+vk.encode().hex(),"sig":base64.b64encode(sig).decode("ascii")}
    return r

def test_valid():
    r = sign(make_base())
    assert verify_signature(r)["ok"] is True

def test_bad_sig():
    r = sign(make_base()); r["output_hash"] = "c"*64
    res = verify_signature(r)
    assert res["ok"] is False

def test_not_present():
    r = make_base()
    res = verify_signature(r)
    assert res["ok"] is False and res["reason"] == "not_provided"
