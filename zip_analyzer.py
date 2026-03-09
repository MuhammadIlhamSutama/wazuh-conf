#!/usr/bin/env python3
import os
import sys
import json
import hashlib
import zipfile
import tarfile
import rarfile

CHUNK_SIZE = 8192

# =========================
# SINGLE-PASS STREAM ANALYZER
# =========================
def analyze_stream(fileobj):
    sha256 = hashlib.sha256()
    is_pe = False
    first_chunk = True
    while True:
        chunk = fileobj.read(CHUNK_SIZE)
        if not chunk: break
        if first_chunk:
            if chunk.startswith(b"MZ"): is_pe = True
            first_chunk = False
        sha256.update(chunk)
    return sha256.hexdigest(), is_pe

# =========================
# MAIN ARCHIVE ANALYZER
# =========================
def analyze_archive(path, password="infected"):
    results = []
    if not os.path.exists(path): return results
    lower = path.lower()
    pwd_bytes = password.encode('utf-8')
    
    # === ZIP ===
    if lower.endswith(".zip"):
        try:
            with zipfile.ZipFile(path, 'r') as z:
                for info in z.infolist():
                    if info.is_dir(): continue
                    try:
                        with z.open(info, 'r', pwd=pwd_bytes) as f:
                            file_hash, is_pe = analyze_stream(f)
                            results.append({"filename": info.filename, "sha256": file_hash, "is_pe": is_pe})
                    except: pass
        except: pass
        
    # === TAR/GZ ===
    elif lower.endswith((".tar", ".gz", ".tgz")):
        try:
            with tarfile.open(path, 'r:*') as tar:
                for member in tar.getmembers():
                    if not member.isfile(): continue
                    f = tar.extractfile(member)
                    if f:
                        file_hash, is_pe = analyze_stream(f)
                        results.append({"filename": member.name, "sha256": file_hash, "is_pe": is_pe})
        except: pass

    # === RAR ===
    elif lower.endswith(".rar"):
        try:
            with rarfile.RarFile(path, 'r') as rar:
                for info in rar.infolist():
                    if info.is_dir(): continue
                    try:
                        with rar.open(info, 'r', pwd=password) as f:
                            file_hash, is_pe = analyze_stream(f)
                            results.append({"filename": info.filename, "sha256": file_hash, "is_pe": is_pe})
                    except: pass
        except: pass

    return results

# =========================
# WAZUH ACTIVE RESPONSE INTEGRATION
# =========================
def main():
    # 1. Wazuh mengirim alert ke STDIN dalam format JSON
    input_data = sys.stdin.read()
    if not input_data:
        return
        
    try:
        alert = json.loads(input_data)
        
        # 2. Ambil path file ZIP dari alert FIM Wazuh
        file_path = alert.get("parameters", {}).get("alert", {}).get("syscheck", {}).get("path")
        if not file_path:
            file_path = alert.get("syscheck", {}).get("path") # Fallback Wazuh versi lama
            
        if not file_path or not os.path.exists(file_path):
            return

        # 3. Jalankan Analisis (Membongkar ZIP tanpa ekstrak)
        data = analyze_archive(file_path)

        # 4. Tulis hasil ke file log Active Response (Agar dibaca balik oleh Manager)
        log_file = "/var/ossec/logs/active-responses.log"
        with open(log_file, "a") as f:
            for item in data:
                # Format: wazuh-zip-analyzer: {"archive": "/tmp/a.zip", "file": "virus.exe", ...}
                log_entry = {
                    "archive_path": file_path,
                    "file_inside": item["filename"],
                    "sha256": item["sha256"],
                    "is_pe": item["is_pe"]
                }
                f.write(f"wazuh-zip-analyzer: {json.dumps(log_entry)}\n")

    except Exception as e:
        with open("/var/ossec/logs/active-responses.log", "a") as f:
            f.write(f"wazuh-zip-analyzer: ERROR {str(e)}\n")

if __name__ == "__main__":
    main()