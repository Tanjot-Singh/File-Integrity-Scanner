# sign_report.py
import os
import json
import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

def load_private_key():
    # Prefer env var (Replit Secrets). Fallback to file.
    pem = os.environ.get("PRIVATE_KEY_PEM")
    if pem:
        key_bytes = pem.encode()
    else:
        with open("private_key.pem","rb") as f:
            key_bytes = f.read()
    return serialization.load_pem_private_key(key_bytes, password=None)

def canonical_bytes(obj):
    return json.dumps(obj, sort_keys=True, separators=(",",":")).encode("utf-8")

def sign_report(input_json_path, output_json_path):
        with open(input_json_path,"r",encoding="utf-8") as f:
            data = json.load(f)

        # Wrap list data into a dict for signing
        if isinstance(data, list):
            report = {"files": data}
        else:
            report = data

        blob = canonical_bytes(report)
        priv = load_private_key()
        sig = priv.sign(blob, ec.ECDSA(hashes.SHA256()))
        report["signature_b64"] = base64.b64encode(sig).decode("ascii")

        with open(output_json_path,"w",encoding="utf-8") as f:
            json.dump(report, f, indent=2)

        print(f"Signed report written to {output_json_path}")


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 3:
        print("Usage: python3 sign_report.py report.json report_signed.json")
        sys.exit(1)
    sign_report(sys.argv[1], sys.argv[2])
