from flask import Flask, request, jsonify
import requests
import os
import hashlib

app = Flask(__name__)
DOWNLOAD_DIR = "/home/pi"
os.makedirs(DOWNLOAD_DIR, exist_ok=True)

def download_file(url, filename):
    response = requests.get(url)
    response.raise_for_status()
    filepath = os.path.join(DOWNLOAD_DIR, filename)
    with open(filepath, "wb") as f:
        f.write(response.content)
    return filepath

def verify_sha256(filepath, expected_digest):
    with open(filepath, "rb") as f:
        file_digest = hashlib.sha256(f.read()).hexdigest()
    return file_digest == expected_digest

@app.route("/download", methods=["POST"])
def download_endpoint():
    """
    Expected JSON payload:
    {
        "files": [
            {"url": "http://pc_host/fw.bin", "filename": "fw.bin", "sha256": "abc123..."},
            {"url": "http://pc_host/key.bin", "filename": "key.bin", "sha256": "def456..."}
        ]
    }
    """
    data = request.json
    if not data or "files" not in data:
        return "No files provided", 400

    downloaded_files = []
    for f in data["files"]:
        try:
            url = f["url"]
            filename = f["filename"]
            expected_sha = f.get("sha256")
            
            filepath = download_file(url, filename)

            if expected_sha:
                if not verify_sha256(filepath, expected_sha):
                    return f"SHA256 mismatch for {filename}", 400
                else:
                    print(f"SHA256 match for {filename}")

            downloaded_files.append(filepath)

        except Exception as e:
            return f"Error downloading {filename}: {e}", 500

    print("Processing files:", downloaded_files)

    return jsonify({"status": "success", "files": downloaded_files})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
