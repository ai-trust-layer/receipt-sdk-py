import sys, json, hashlib
from common_canonical import canonicalize_subset_bytes

p = sys.argv[1]
r = json.load(open(p, "r", encoding="utf-8"))
b = canonicalize_subset_bytes(r)
h = hashlib.sha256(b).hexdigest()
print("PY CANON_STR:", b.decode("utf-8"))
print("PY CANON_SHA256:", h)
