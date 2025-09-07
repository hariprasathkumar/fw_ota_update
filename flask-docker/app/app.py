from flask import Flask, request, render_template, send_from_directory
import hashlib, requests, os

app = Flask(__name__)
SERVER_IP = "http://192.168.1.103:5000"
PI_CLIENT = "http://192.168.1.101:5000"

@app.route("/")
def index():
    try:
        status = requests.get(f"{PI_CLIENT}/status").text.strip()
        in_progress = requests.get(f"{PI_CLIENT}/progress").text.strip()
    except Exception:
        status = "Error connecting to Pi"
        in_progress = "N/A"
    return render_template("index.html", status=status, in_progress=in_progress)

@app.route('/upload', methods=['POST'])
def upload():
    file1 = request.files.get('fw')
    file2 = request.files.get('key')

    if not file1 or not file2:
        return "Please upload both files", 400

    file1.save(file1.filename)
    file2.save(file2.filename)

    with open(file1.filename, "rb") as f:
        digest1 = hashlib.sha256(f.read()).hexdigest()
    with open(file2.filename, "rb") as f:
        digest2 = hashlib.sha256(f.read()).hexdigest()

    payload = {
        "files": [
            {"url": f"{SERVER_IP}/ti_buck_fw.bin", "filename": file1.filename, "sha256": digest1},
            {"url": f"{SERVER_IP}/ti_buck_fw_key.bin", "filename": file2.filename, "sha256": digest2}
        ]
    }

    try:
        response = requests.post(f"{PI_CLIENT}/download", json=payload, timeout=10)
        return f"Pi response: {response.text}"
    except Exception as e:
        return f"Failed to contact Pi: {e}"

@app.route('/ti_buck_fw.bin')
def serve_fw():
    return send_from_directory(os.getcwd(), "ti_buck_fw.bin")

@app.route('/ti_buck_fw_key.bin')
def serve_key():
    return send_from_directory(os.getcwd(), "ti_buck_fw_key.bin")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
