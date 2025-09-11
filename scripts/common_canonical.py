import json

SUBSET_KEYS = ["id","issued_at","input_hash","output_hash","model_version","policy_version"]

def canonicalize_subset_bytes(receipt: dict) -> bytes:
    obj = {}
    for k in SUBSET_KEYS:
        if k not in receipt:
            raise ValueError(f"missing {k}")
        obj[k] = receipt[k]
    s = json.dumps(obj, separators=(',', ':'), ensure_ascii=False)
    return s.encode('utf-8')
