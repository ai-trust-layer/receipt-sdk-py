import base64, json, re
from typing import Iterable, Dict, Any, Optional

try:
    from nacl.signing import VerifyKey
    from nacl.exceptions import BadSignatureError
    _HAS_NACL = True
except Exception:
    _HAS_NACL = False

_CANON_KEYS = ("id","issued_at","input_hash","output_hash","model_version","policy_version")

def canonicalize_subset(data: Dict[str, Any], keys: Iterable[str] = _CANON_KEYS) -> str:
    sub = {k: data[k] for k in keys if k in data}
    return json.dumps(sub, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")

def _maybe_hex(s: str) -> Optional[bytes]:
    if s.startswith("0x") and _HEX_RE.fullmatch(s[2:]) and (len(s)-2) % 2 == 0:
        return bytes.fromhex(s[2:])
    if _HEX_RE.fullmatch(s) and (len(s) % 2 == 0):
        return bytes.fromhex(s)
    return None

def _b64_any(s: str) -> bytes:
    # încearcă base64 standard
    try:
        return base64.b64decode(s, validate=True)
    except Exception:
        pass
    # încearcă base64-url (fără/ cu padding)
    t = s.replace("-", "+").replace("_", "/")
    pad = (-len(t)) % 4
    t = t + ("=" * pad)
    return base64.b64decode(t)

def _to_bytes(s: Any) -> bytes:
    if isinstance(s, bytes):
        return s
    if isinstance(s, str):
        hx = _maybe_hex(s)
        if hx is not None:
            return hx
        return _b64_any(s)
    raise TypeError("expected str/bytes")

def _extract_str(val: Any) -> Optional[str]:
    if val is None:
        return None
    if isinstance(val, str):
        return val
    if isinstance(val, dict):
        # suport pentru forme înrădăcinate: {"value": "...", "format": "base64"|"hex"}
        return val.get("value") or val.get("data") or val.get("raw")
    return None

def _extract_sig_fields(sig_obj: Any):
    """Returnează (public_key, signature, algo) din diverse convenții de nume sau structuri înrădăcinate."""
    if not isinstance(sig_obj, dict):
        return None, None, None
    algo = (_extract_str(sig_obj.get("algo"))
            or _extract_str(sig_obj.get("alg"))
            or _extract_str(sig_obj.get("algorithm"))
            or "ed25519").lower()
    public_key = (_extract_str(sig_obj.get("public_key"))
                  or _extract_str(sig_obj.get("publicKey"))
                  or _extract_str(sig_obj.get("pubkey"))
                  or _extract_str(sig_obj.get("key")))
    signature = (_extract_str(sig_obj.get("value"))
                 or _extract_str(sig_obj.get("sig"))
                 or _extract_str(sig_obj.get("signature"))
                 or _extract_str(sig_obj.get("signature_b64")))
    return public_key, signature, algo

def verify_signature(
    receipt: Dict[str, Any],
    public_key: Optional[str] = None,
    signature: Optional[str] = None,
    algo: Optional[str] = None
) -> Dict[str, Any]:
    sig_obj = receipt.get("signature") if isinstance(receipt, dict) else None

    pk, sig, alg = public_key, signature, (algo.lower() if isinstance(algo, str) else None)
    spk, ssig, salg = _extract_sig_fields(sig_obj)
    if pk is None: pk = spk
    if sig is None: sig = ssig
    if alg is None: alg = (salg or "ed25519")

    if pk is None or sig is None:
        return {"ok": False, "reason": "not_provided"}

    if alg != "ed25519":
        return {"ok": False, "reason": "unsupported_algo"}

    if not _HAS_NACL:
        return {"ok": False, "reason": "not_implemented"}

    msg = canonicalize_subset(receipt).encode("utf-8")
    try:
        VerifyKey(_to_bytes(pk)).verify(msg, _to_bytes(sig))
        return {"ok": True, "reason": "ok"}
    except BadSignatureError:
        return {"ok": False, "reason": "bad_signature"}
