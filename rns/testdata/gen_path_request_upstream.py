"""Generate rns/testdata/path_request_upstream.json from upstream RNS.

SPEC §7.1 / §7.2.1: path-request payloads in each form upstream accepts,
with the tuple upstream's own Transport.parse_path_request splits them
into. The stamped case uses a stamp from Transport.stamp_path_request, and
the placeholder case is the 0xC1 0xFF filler a relay appends when it
forwards an unstamped request.

Run with an upstream `rns` (>= 1.6.0) installed:
    python gen_path_request_upstream.py > path_request_upstream.json
"""
import hashlib, json
import RNS

T = RNS.Transport

def b(label):  # fixed bytes, so only the stamp differs between runs
    return hashlib.sha256(label.encode()).digest()[:16]

dst, tid, tag = b("target"), b("transport_id"), b("tag")
_, ext = T.stamp_path_request(dst, tag=tag, return_payload=True)
placeholder = bytes([RNS.Identity.EXTPAYLOADMARKER, 0xFF]) + bytes(RNS.Identity.STAMPLENGTH)

cases = []
for name, data in (
    ("stamped", dst + tid + tag + ext),
    ("relayed_placeholder", dst + tid + tag + placeholder),
    ("unstamped", dst + tid + tag),
    ("legacy", dst + tag),
):
    d, i, g, e = T.parse_path_request(data)
    stamp_valid = bool(e) and T.validate_pr_stamp(e[2:], d, g)
    cases.append({
        "name": name,
        "payload_hex": data.hex(),
        "target_hex": d.hex(),
        "transport_id_hex": (i or b"").hex(),
        "tag_hex": g.hex(),
        "ext_hex": (e or b"").hex(),
        "stamp_valid_at_pr_cost": stamp_valid,
    })

print(json.dumps({
    "_about": "SPEC §7.2.1 path-request payloads and upstream Transport.parse_path_request results; stamp from Transport.stamp_path_request.",
    "rns_version_at_generation": RNS.__version__,
    "pr_cost": T.PR_COST,
    "cases": cases,
}, indent=2))
