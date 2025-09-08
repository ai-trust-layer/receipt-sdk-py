from __future__ import annotations
import json, hashlib, pathlib
from typing import Any, Dict, List, Optional
from jsonschema import Draft202012Validator

SCHEMA_PATH = pathlib.Path(__file__).resolve().parent / "schema" / "receipt.schema.json"
SCHEMA = json.loads(SCHEMA_PATH.read_text())

def validate_schema(receipt: Dict[str, Any]) -> Dict[str, Any]:
    v = Draft202012Validator(SCHEMA)
    errors = sorted(v.iter_errors(receipt), key=lambda e: list(e.path))
    return {"ok": len(errors) == 0, "errors": [e.message for e in errors]}

def _sha256_hex_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def _strip_prefix(v: str) -> str:
    return (v or "").lower().removeprefix("sha256:")

def _apply_salt(data: bytes, salt_hex: Optional[str], mode: str) -> bytes:
    if not salt_hex:
        return data
    salt = bytes.fromhex(salt_hex.replace("0x",""))
    return (salt + data) if mode == "prefix" else (data + salt)

def verify_hashes(receipt: Dict[str, Any], input_path: Optional[str]=None, output_path: Optional[str]=None,
                  salt_hex: Optional[str]=None, mode: str="prefix") -> Dict[str, Any]:
    results: List[Dict[str, Any]] = []
    if receipt.get("input_hash") and input_path:
        data = pathlib.Path(input_path).read_bytes()
        calc = _sha256_hex_bytes(_apply_salt(data, salt_hex, mode))
        results.append({"field":"input_hash", "ok": _strip_prefix(receipt["input_hash"]) == calc})
    if receipt.get("output_hash") and output_path:
        data = pathlib.Path(output_path).read_bytes()
        calc = _sha256_hex_bytes(_apply_salt(data, salt_hex, mode))
        results.append({"field":"output_hash", "ok": _strip_prefix(receipt["output_hash"]) == calc})
    ok = all(r["ok"] for r in results) if results else True
    return {"ok": ok, "details": results}

def verify_anchor(receipt: Dict[str, Any]) -> Dict[str, Any]:
    prs = receipt.get("proof_refs") or []
    ok = isinstance(prs, list) and all(isinstance(p, dict) and all(k in p for k in ("type","network","tx")) for p in prs)
    return {"ok": ok, "count": len(prs)}

def verify_signature(receipt: Dict[str, Any]) -> Dict[str, Any]:
    return {"ok": False, "reason": "not_implemented"}

def verify_receipt(receipt: Dict[str, Any], input_path: Optional[str]=None, output_path: Optional[str]=None,
                   salt_hex: Optional[str]=None, mode: str="prefix") -> Dict[str, Any]:
    s = validate_schema(receipt)
    a = verify_anchor(receipt)
    h = verify_hashes(receipt, input_path, output_path, salt_hex, mode)
    verdict = bool(s["ok"] and a["ok"] and h["ok"])
    return {"verdict": "PASS" if verdict else "FAIL",
            "checks": {"schema": s, "anchor": a, "hashes": h, "signature": verify_signature(receipt)}}
