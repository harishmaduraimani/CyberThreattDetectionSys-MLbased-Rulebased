import json
import os
from datetime import datetime
from flask import Flask, jsonify, render_template, request
from werkzeug.utils import secure_filename


from detectors.file_detector import detect_file
from detectors.port_scanner import detect_open_ports
from detectors.url_detector import detect_url
from engine.risk_engine import RiskEngine


app = Flask(__name__)
risk_engine = RiskEngine()

HASH_DATABASE = "data/hashes.txt"
HISTORY_FILE = "storage/scan_history.json"
UPLOAD_FOLDER = "uploads"


def result_to_dict(result):
    return {
        "detector": result.detectorname,
        "risk_score": result.riskscore,
        "verdict": result.perdict,
        "reason": result.reason,
        "parameters": result.parameters
    }


def save_scan(scan_type, user_input, result):
    os.makedirs("storage", exist_ok=True)

    record = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "scan_type": scan_type,
        "input": user_input,
        **result_to_dict(result)
    }

    history = []
    if os.path.exists(HISTORY_FILE):
        with open(HISTORY_FILE, "r") as file:
            history = json.load(file)

    history.append(record)

    with open(HISTORY_FILE, "w") as file:
        json.dump(history, file, indent=4)

    return record


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/api/scan/file", methods=["POST"])
def scan_file():
    uploaded_file = request.files.get("file")

    if uploaded_file is None or uploaded_file.filename == "":
        return jsonify({"error": "Please choose a file to scan"}), 400

    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    os.makedirs("data", exist_ok=True)

    if not os.path.exists(HASH_DATABASE):
        open(HASH_DATABASE, "a").close()

    safe_name = secure_filename(uploaded_file.filename)
    saved_path = os.path.join(UPLOAD_FOLDER, safe_name)
    uploaded_file.save(saved_path)

    raw_result = detect_file(saved_path, HASH_DATABASE)
    final_result = risk_engine.evaluate_single_result(raw_result)

    record = save_scan("file", safe_name, final_result)
    return jsonify(record)


@app.route("/api/scan/url", methods=["POST"])
def scan_url():
    data = request.get_json()
    url = data.get("url", "").strip()

    if not url:
        return jsonify({"error": "Please enter a URL"}), 400

    raw_result = detect_url(url)
    final_result = risk_engine.evaluate_single_result(raw_result)

    record = save_scan("url", url, final_result)
    return jsonify(record)

@app.route("/api/scan/ports", methods=["POST"])
def scan_ports():
    data = request.get_json()

    # Frontend may send "host"; older backend may expect "target"
    target = data.get("host", data.get("target", "")).strip()

    # Ports can be optional
    ports = data.get("ports")

    if not target:
        return jsonify({"error": "Please enter a target host"}), 400

    # If no ports are given, scanner will use common ports
    if not ports:
        ports = None

    raw_result = detect_open_ports(target, ports)
    final_result = risk_engine.evaluate_single_result(raw_result)

    record = save_scan("port", {"target": target, "ports": ports}, final_result)
    return jsonify(record)

def dummy_ai_answer(question):
    lower_question = question.lower()
    return (
        "Dummy AI: I am a placeholder cybersecurity assistant. Later, you can replace "
        "me with a real LLM API while keeping the same frontend and Flask route."
    )


@app.route("/api/ask", methods=["POST"])
def ask_ai():
    data = request.get_json()
    question = data.get("question", "").strip()

    if not question:
        return jsonify({"error": "Please enter a question"}), 400

    answer = dummy_ai_answer(question)

    return jsonify({
        "question": question,
        "answer": answer
    })



@app.route("/api/history")
def get_history():
    if not os.path.exists(HISTORY_FILE):
        return jsonify([])

    with open(HISTORY_FILE, "r") as file:
        return jsonify(json.load(file))


if __name__ == "__main__":
    app.run(debug=True)