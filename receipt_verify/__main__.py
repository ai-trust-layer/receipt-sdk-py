import json, sys
from pathlib import Path
import click
from . import validate_schema, verify_hashes, compute_trust_score

@click.group()
def cli():
    pass

@cli.command()
@click.argument("receipt_json", type=click.Path(exists=True))
@click.option("--schema", "schema_path", required=True, type=click.Path(exists=True))
@click.option("--input", "input_path", type=click.Path())
@click.option("--output","output_path", type=click.Path())
def verify(receipt_json, schema_path, input_path, output_path):
    receipt = json.loads(Path(receipt_json).read_text())
    schema  = json.loads(Path(schema_path).read_text())
    sres = validate_schema(receipt, schema)
    hres = {"ok": False, "input": False, "output": False}
    if input_path and output_path and Path(input_path).exists() and Path(output_path).exists():
        hres = verify_hashes(Path(input_path).read_bytes(), Path(output_path).read_bytes(), receipt)
    score = compute_trust_score({"schema": sres["ok"], "hashes": hres["ok"], "signature": False, "anchor": False})
    result = {
        "pass": sres["ok"] and hres["ok"],
        "schema_ok": sres["ok"],
        "schema_errors": sres["errors"],
        "hashes_ok": hres["ok"],
        "details": {"hashes": hres},
        "trust_score": score
    }
    click.echo(json.dumps(result, indent=2))
    sys.exit(0 if result["pass"] else 1)

if __name__ == "__main__":
    cli()
