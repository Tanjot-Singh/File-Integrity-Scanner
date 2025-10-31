import os, json, base64, mimetypes
from colorama import Fore, Style, init
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

init(autoreset=True)

# ---------- Color Table ----------
def print_color_table(results):
    print(f"\n{'File Name':30} | {'Type':25} | {'Risk'}")
    print("-" * 70)
    for result in results:
        name = os.path.basename(result['path'])
        ftype = result['type']
        risk = result['risk'].upper()
        if risk == "CLEAN":
            color = Fore.GREEN
        elif risk == "SUSPICIOUS":
            color = Fore.YELLOW
        else:
            color = Fore.RED
        print(f"{name:30} | {ftype:25} | {color}{risk}{Style.RESET_ALL}")

    total = len(results)
    clean = sum(1 for r in results if r['risk'].upper() == "CLEAN")
    suspicious = sum(1 for r in results if r['risk'].upper() == "SUSPICIOUS")
    unknown = total - clean - suspicious

    print("-" * 70)
    print(f"Total files scanned: {total}")
    print(f"{Fore.GREEN}Clean: {clean}{Style.RESET_ALL} | {Fore.YELLOW}Suspicious: {suspicious}{Style.RESET_ALL} | {Fore.RED}Unknown: {unknown}{Style.RESET_ALL}")


# ---------- File Scanning ----------
def get_file_type(path):
    mime, _ = mimetypes.guess_type(path)
    return mime or "unknown"

def classify_file(mime):
    """Assign a basic risk level based on file type."""
    if mime.startswith("text/") or "image" in mime:
        return "CLEAN"
    elif "application/x-dosexec" in mime or (mime and mime.endswith("exe")):
        return "SUSPICIOUS"
    else:
        return "UNKNOWN"

def colorize(label, text):
    """Return colorized text based on label."""
    if label == "CLEAN":
        return Fore.GREEN + text + Style.RESET_ALL
    elif label == "SUSPICIOUS":
        return Fore.RED + text + Style.RESET_ALL
    else:
        return Fore.YELLOW + text + Style.RESET_ALL

def scan_file(file_path):
    file_type = get_file_type(file_path)
    risk = classify_file(file_type)
    print(colorize(risk, f"{file_path:<30} → {file_type}"))
    return {"path": file_path, "type": file_type, "risk": risk}

def scan_path(scan_dir):
    results = []
    for root, dirs, files in os.walk(scan_dir):
        for name in files:
            file_path = os.path.join(root, name)
            result = scan_file(file_path)
            results.append(result)
    return results


# ---------- Signing ----------
def canonical_bytes(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")

def sign_report(report, privkey_path):
    with open(privkey_path, "rb") as f:
        priv = serialization.load_pem_private_key(f.read(), password=None)
    blob = canonical_bytes(report)
    sig = priv.sign(blob, ec.ECDSA(hashes.SHA256()))
    report["signature_b64"] = base64.b64encode(sig).decode("ascii")
    return report


# ---------- Save Output ----------
def save_report(report, output_path):
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    print(f"\n✅ Signed report saved as {output_path}")


# ---------- Main ----------
if __name__ == "__main__":
    import sys
    scan_dir = sys.argv[1]
    report_file = sys.argv[2]

    results = scan_path(scan_dir)

    # Write JSON report
    with open(report_file, "w") as f:
        json.dump(results, f, indent=2)

    # Print color table summary
    print_color_table(results)
    print(f"\nReport saved to {report_file}")
