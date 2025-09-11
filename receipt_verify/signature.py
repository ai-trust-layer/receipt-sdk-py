import base64, json
from typing import Any, Dict
from nacl.signing import VerifyKey
from nacl.exceptions import BadSignatureError

SUBSET_KEYS = ["id","issued_at","input_hash","output_hash","model_version","policy_version"]

def _sort_obj(o: Any) -> Any:
    if isinstance(o, list):
        return [_sort_obj(x) for x in o]
    if isinstance(o, dict):
        return {k: _sort_obj(o[k]) for k in sorted(o.keys())}
    return o

def canonicalize_subset(receipt: Dict[str, Any]) -> str:
    obj = {k: receipt[k] for k in SUBSET_KEYS if k in receipt}
    return json.dumps(_sort_obj(obj), separators=(',', ':'), ensure_ascii=False)

def verify_signature(receipt: Dict[str, Any]) -> Dict[str, Any]:
    sigobj = receipt.get("signature")
    if not sigobj:
        return {"ok": False, "reason": "not_provided"}
    if sigobj.get("alg") != "ed25519":
        return {"ok": False, "reason": "alg_unsupported"}
    sig_b64 = sigobj.get("sig")
    if not sig_b64:
        return {"ok": False, "reason": "sig_missing"}
    kid = sigobj.get("kid", "")
    pubhex = kid.split(":", 1)[1] if isinstance(kid, str) and kid.startswith("ed25519:") else None
    if not pubhex:
        return {"ok": False, "reason": "kid_unresolved"}
    try:
        msg = canonicalize_subset(receipt).encode("utf-8")
        sig = base64.b64decode(sig_b64)
        pub = bytes.fromhex(pubhex)
        vk = VerifyKey(pub)
        vk.verify(msg, sig)
        return {"ok": True}
    except BadSignatureError:
        return {"ok": False, "reason": "bad_signature"}
    except Exception as e:
        return {"ok": False, "reason": "verify_error", "error": str(e)}
