import os
from flask import Flask, request, jsonify
from flask_cors import CORS
from werkzeug.utils import secure_filename
from androguard.core.bytecodes.apk import APK

app = Flask(__name__)
CORS(app)

UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
ALLOWED_EXTENSIONS = {".apk"}

def allowed_file(filename):
    return any(filename.lower().endswith(ext) for ext in ALLOWED_EXTENSIONS)

def analyze_apk(file_path):
    """ Extract basic APK features """
    apk = APK(file_path)

    app_name = apk.get_app_name()
    package_name = apk.package
    version = apk.get_androidversion_name()
    permissions = apk.get_permissions()
    file_size_kb = round(os.path.getsize(file_path) / 1024, 2)

    return {
        "App Name": app_name,
        "Package Name": package_name,
        "Version": version,
        "Permissions": permissions,
        "File Size (KB)": file_size_kb
    }

def detect_fake(features):
    """ Rule-based fake APK detection """
    suspicious = []

    # Rule 1: Package name should follow common pattern
    if not (features["Package Name"].startswith("com.") or 
            features["Package Name"].startswith("org.") or 
            features["Package Name"].startswith("in.")):
        suspicious.append("Unusual package name")

    # Rule 2: File size check
    if features["File Size (KB)"] < 2000:
        suspicious.append("APK size unusually small")

    # Rule 3: Suspicious permissions
    dangerous_perms = ["READ_SMS", "READ_CONTACTS", "RECORD_AUDIO"]
    for perm in dangerous_perms:
        if perm in features["Permissions"]:
            suspicious.append(f"Suspicious Permission: {perm}")

    if suspicious:
        return {"Verdict": "Likely FAKE ⚠️", "Reasons": suspicious}
    return {"Verdict": "SAFE ✅", "Reasons": []}

@app.route("/scan", methods=["POST"])
def scan_apk():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files["file"]
    filename = secure_filename(file.filename)
    if not allowed_file(filename):
        return jsonify({"error": "Please upload a .apk file"}), 400

    path = os.path.join(UPLOAD_FOLDER, filename)
    file.save(path)

    try:
        features = analyze_apk(path)
        result = detect_fake(features)
        return jsonify({"features": features, "result": result})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        os.remove(path)

if __name__ == "__main__":
    app.run(debug=True, port=5000)
