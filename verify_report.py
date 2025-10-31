# verify_report.py
import json, base64, sys
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature

def canonical_bytes(obj):
    return json.dumps(obj, sort_keys=True, separators=(",",":")).encode("utf-8")

def verify_report(signed_json_path, pubkey_path):
    with open(signed_json_path,"r",encoding="utf-8") as f:
        report = json.load(f)

    # Extract and remove signature
    sig_b64 = report.pop("signature_b64", None)
    if not sig_b64:
        print("❌ No signature found in report.")
        return False

    sig = base64.b64decode(sig_b64)
    blob = canonical_bytes(report)

    # Load public key
    with open(pubkey_path,"rb") as f:
        pub = serialization.load_pem_public_key(f.read())

    # Verify
    try:
        pub.verify(sig, blob, ec.ECDSA(hashes.SHA256()))
        print("✅ VERIFY OK — signature valid.")
        return True
    except InvalidSignature:
        print("❌ INVALID SIGNATURE.")
        return False

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 verify_report.py report_signed.json public_key.pem")
        sys.exit(1)
    ok = verify_report(sys.argv[1], sys.argv[2])
    sys.exit(0 if ok else 2)
