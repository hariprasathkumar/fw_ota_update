from flask import Flask, request, render_template
import hashlib
import requests

app = Flask(__name__)
files = {}
RASPBERRY_PI_IP = "10.225.209.10"
SERVER_IP = "10.225.209.24"

@app.route("/")
def index():
    return render_template("index.html")

@app.route('/upload', methods=['POST'])
def upload():
    file1 = request.files.get('fw')
    file2 = request.files.get('key')

    if not file1 or not file2:
        return "Please upload both files", 400

    try:
        file1.save(file1.filename)
        with open(file1.filename, "rb") as f:
            digest1 = hashlib.sha256(f.read()).hexdigest()

        file2.save(file2.filename)
        with open(file2.filename, "rb") as f:
            digest2 = hashlib.sha256(f.read()).hexdigest()

        files['fw'] = True
        files['key'] = True

    except Exception as e:
        files['fw'] = files['key'] = False
        return f"Error saving files: {e}", 500

    pi_url = f"http://{RASPBERRY_PI_IP}:5000/download"
    server_url = f"http://{SERVER_IP}:5000/"
    payload = {
        "files": [
            {"url": server_url+"ti_buck_fw.bin", "filename": file1.filename, "sha256": digest1},
            {"url": server_url+"ti_buck_fw_key.bin", "filename": file2.filename, "sha256": digest2}
        ]
    }

    try:
        response = requests.post(pi_url, json=payload, timeout=10)
        return f"Pi response: {response.text}"
    except Exception as e:
        return f"Failed to contact Pi: {e}"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
