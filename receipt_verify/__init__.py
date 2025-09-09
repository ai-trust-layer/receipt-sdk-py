__all__ = ["validate_schema","verify_hashes","compute_trust_score"]
import hashlib
from jsonschema import Draft202012Validator

def _norm(h:str)->str:
    if not isinstance(h,str): return ""
    h=h.strip().lower()
    return h[7:] if h.startswith("sha256:") else h

def validate_schema(receipt:dict, schema:dict):
    v = Draft202012Validator(schema)
    errs = sorted(v.iter_errors(receipt), key=lambda e: e.path)
    return {"ok": len(errs)==0, "errors": [e.message for e in errs]}

def verify_hashes(input_bytes:bytes, output_bytes:bytes, receipt:dict):
    ih = hashlib.sha256(input_bytes).hexdigest()
    oh = hashlib.sha256(output_bytes).hexdigest()
    ok_in = _norm(receipt.get("input_hash","")) == ih
    ok_out = _norm(receipt.get("output_hash","")) == oh
    return {"ok": ok_in and ok_out, "input": ok_in, "output": ok_out}

def compute_trust_score(parts:dict)->int:
    w = {"schema":0.5,"hashes":0.4,"signature":0.05,"anchor":0.05}
    s = 0
    if parts.get("schema"): s += 100*w["schema"]
    if parts.get("hashes"): s += 100*w["hashes"]
    if parts.get("signature"): s += 100*w["signature"]
    if parts.get("anchor"): s += 100*w["anchor"]
    return round(s)
