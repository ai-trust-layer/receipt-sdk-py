import argparse, json, sys
from jsonschema import Draft7Validator

def load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def validate_schema(obj, schema_path):
    schema = load_json(schema_path)
    v = Draft7Validator(schema)
    errors = sorted(v.iter_errors(obj), key=lambda e: e.path)
    return {"ok": len(errors) == 0, "errors": [e.message for e in errors]}

def main():
    p = argparse.ArgumentParser(prog="receipt_verify", add_help=True)
    p.add_argument("receipt", help="path to receipt.json")
    p.add_argument("--schema", required=True, help="path to JSON Schema")
    p.add_argument("--schema-only", action="store_true", help="validate only against schema (skip hashes/signature)")
    p.add_argument("--input", help="optional input file to hash-verify (not used in schema-only)")
    p.add_argument("--output", help="optional output file to hash-verify (not used in schema-only)")
    args = p.parse_args()

    receipt = load_json(args.receipt)
    sres = validate_schema(receipt, args.schema)

    hashes = {"ok": False, "input": False, "output": False}

    if args.schema_only:
        result = {
            "pass": bool(sres["ok"]),
            "schema_ok": bool(sres["ok"]),
            "schema_errors": sres["errors"],
            "hashes_ok": False,
            "details": {"hashes": hashes},
            "hashes_mode": "skipped",
            "trust_score": 100 if sres["ok"] else 0
        }
        print(json.dumps(result, indent=2))
        sys.exit(0 if result["pass"] else 1)

    result = {
        "pass": bool(sres["ok"]) and bool(hashes["ok"]),
        "schema_ok": bool(sres["ok"]),
        "schema_errors": sres["errors"],
        "hashes_ok": bool(hashes["ok"]),
        "details": {"hashes": hashes},
        "trust_score": 100 if sres["ok"] and hashes["ok"] else 0
    }
    print(json.dumps(result, indent=2))
    sys.exit(0 if result["pass"] else 1)

if __name__ == "__main__":
    main()
