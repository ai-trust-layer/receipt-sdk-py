from __future__ import annotations
import json, hashlib, pathlib
from typing import Any, Dict, List, Optional
from jsonschema import Draft202012Validator

SCHEMA_PATH = pathlib.Path(__file__).resolve().parent.parent / "schema" / "receipt.schema.json"
SCHEMA = json.loads(SCHEMA_PATH.read_text())

def validate_schema(receipt: Dict[str, Any]) -> Dict[str, Any]:
    v = Draft202012Validator(SCHEMA)
    errors = sorted(v.iter_errors(receipt), key=lambda e: e.path)
    return {"ok": len(errors) == 0, "errors": [e.message for e in errors]}

def _sha256_hex(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

def _strip_prefix(v: str) -> str:
    return (v or "").lower().removeprefix("sha256:")

def verify_hashes(receipt: Dict[str, Any], input_path: Optional[str]=None, output_path: Optional[str]=None) -> Dict[str, Any]:
    res: List[Dict[str, Any]] = []
    if receipt.get("input_hash") and input_path:
        res.append({"field":"input_hash", "ok": _strip_prefix(receipt["input_hash"]) == _sha256_hex(pathlib.Path(input_path))})
    if receipt.get("output_hash") and output_path:
        res.append({"field":"output_hash","ok": _strip_prefix(receipt["output_hash"]) == _sha256_hex(pathlib.Path(output_path))})
    ok = all(r["ok"] for r in res) if res else True
    return {"ok": ok, "details": res}

def verify_anchor(receipt: Dict[str, Any]) -> Dict[str, Any]:
    prs = receipt.get("proof_refs") or []
    ok = isinstance(prs, list) and all(isinstance(p, dict) and all(k in p for k in ("type","network","tx")) for p in prs)
    return {"ok": ok, "count": len(prs)}

def verify_signature(receipt: Dict[str, Any]) -> Dict[str, Any]:
    return {"ok": False, "reason": "not_implemented"}

def verify_receipt(receipt: Dict[str, Any], input_path: Optional[str]=None, output_path: Optional[str]=None) -> Dict[str, Any]:
    s = validate_schema(receipt)
    a = verify_anchor(receipt)
    h = verify_hashes(receipt, input_path, output_path)
    verdict = bool(s["ok"] and a["ok"] and h["ok"])
    return {"verdict": "PASS" if verdict else "FAIL", "checks": {"schema": s, "anchor": a, "hashes": h, "signature": verify_signature(receipt)}}
