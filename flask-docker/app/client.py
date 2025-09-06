from flask import Flask, request, jsonify
import requests, os, hashlib, shutil

app = Flask(__name__)
DOWNLOAD_DIR = "/home/pi"
os.makedirs(DOWNLOAD_DIR, exist_ok=True)

fw_file = "/lib/firmware/ti_buck_fw.bin"
key_file = "/lib/firmware/ti_buck_fw_key.bin"
TRIGGER_PATH = "/sys/class/pmic_fw_downloader/ti-buck-regulator-pmbus-iv/trigger"
STATUS_PATH = "/sys/class/pmic_fw_downloader/ti-buck-regulator-pmbus-iv/status"
PROGRESS_PATH = "/sys/class/pmic_fw_downloader/ti-buck-regulator-pmbus-iv/progress"

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
    data = request.json
    if not data or "files" not in data:
        return "No files provided", 400

    downloaded_files = []
    for f in data["files"]:
        try:
            filepath = download_file(f["url"], f["filename"])
            if f.get("sha256") and not verify_sha256(filepath, f["sha256"]):
                return f"SHA256 mismatch for {f['filename']}", 400

            if "fw" in f["filename"]:
                shutil.copy(filepath, fw_file)
            else:
                shutil.copy(filepath, key_file)

            downloaded_files.append(filepath)
        except Exception as e:
            return f"Error downloading {f['filename']}: {e}", 500

    with open(TRIGGER_PATH, "w") as f:
        f.write("1\n")

    return jsonify({"status": "success", "files": downloaded_files})

@app.route("/status")
def check_status():
    with open(STATUS_PATH) as f:
        return f.read()

@app.route("/progress")
def check_progress():
    with open(PROGRESS_PATH) as f:
        return f.read()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
