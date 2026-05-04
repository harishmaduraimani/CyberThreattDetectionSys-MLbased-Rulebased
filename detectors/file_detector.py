import hashlib
import os 
from engine.detection_result import DetectionResult

suspicious_ext = [".txt", ".bat", ".cmd", ".scr", ".ps1", ".vbs", ".js"]

def calculate_sha256(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path,'rb') as f:
        for chunk in iter(lambda : f.read(4096), b""):

            sha256_hash.update(chunk)
    print(f"Calculated SHA-256 for {file_path}: {sha256_hash.hexdigest()}")
    return sha256_hash.hexdigest()

def load_known_malware_hashes(hash_file_path):
    known_hashes = set()
    with open(hash_file_path,'r') as f:
        for line in f:
            clean_hash = line.strip()
            if clean_hash:
                known_hashes.add(clean_hash)

    return known_hashes

def has_double_extension(file_name):
    parts = file_name.lower().split(".")
    return len(parts) >=3
def detect_file(file_path, hash_file_path):
    if not os.path.exists(file_path):
        return DetectionResult(
            detectorname="File Malware Detector",
            riskscore=0,
            perdict="Error",
            reason=f"File not found: {file_path}"
        )
    file_name = os.path.basename(file_path)
    file_extension = os.path.splitext(file_name)[1].lower()
    file_size = os.path.getsize(file_path)
    file_hash = calculate_sha256(file_path)
    known_malware_hashes = load_known_malware_hashes(hash_file_path)
    riskscore = 0
    reasons = []
   

    if file_hash in known_malware_hashes:
        riskscore += 90
        reasons.append("File hash matched known malware database")
    if file_extension in suspicious_ext:
        riskscore += 20
        reasons.append(f"File has suspicious extension: {file_extension}")

    if has_double_extension(file_name):
        riskscore += 20
        reasons.append("File uses double extension")

    if file_size > 50 * 1024 * 1024:
        riskscore += 10
        reasons.append("File is larger than 50 MB")

    if riskscore > 100:
        riskscore = 100

    if riskscore >= 70:
        perdict = "Dangerous"
    elif riskscore >= 30:
        perdict = "Suspicious"
    else:
        perdict = "Safe"

    if not reasons:
        reasons.append("No suspicious file indicators found")

    # Return structured result
    return DetectionResult(
        detectorname="File Malware Detector",
        riskscore=riskscore,
        perdict=perdict,
        reason="; ".join(reasons),
        parameters={
        "file_name": file_name,
        "file_extension": file_extension,
        "file_size_bytes": file_size,
        "sha256_hash": file_hash,
        "has_double_extension": has_double_extension(file_name),
        "hash_matched_malware_database": file_hash in known_malware_hashes
    }
    )

