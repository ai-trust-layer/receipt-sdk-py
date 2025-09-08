import argparse, json, sys
from .verify import verify_receipt

def main():
    p = argparse.ArgumentParser(prog="receipt-verify", description="Verify AI Receipt offline")
    p.add_argument("receipt", help="Path to receipt JSON")
    p.add_argument("--input", help="Path to original input (optional)")
    p.add_argument("--output", help="Path to model output (optional)")
    args = p.parse_args()

    with open(args.receipt, "r", encoding="utf-8") as f:
        receipt = json.load(f)

    result = verify_receipt(receipt, args.input, args.output)
    print(json.dumps(result, indent=2))
    sys.exit(0 if result["verdict"] == "PASS" else 2)

if __name__ == "__main__":
    main()
