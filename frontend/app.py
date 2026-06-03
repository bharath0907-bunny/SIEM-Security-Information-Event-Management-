from flask import Flask, jsonify, send_from_directory, abort
import os
import json

app = Flask(__name__, static_folder='')

# Path to alerts JSON (shared volume with AI engine)
ALERTS_FILE = os.path.abspath(os.path.join('..', 'reports', 'alerts.json'))

@app.route('/')
def index():
    return send_from_directory('.', 'index.html')

@app.route('/style.css')
def css():
    return send_from_directory('.', 'style.css')

@app.route('/app.js')
def js():
    return send_from_directory('.', 'app.js')

@app.route('/api/alerts')
def get_alerts():
    if os.path.exists(ALERTS_FILE):
        try:
            with open(ALERTS_FILE, 'r') as f:
                data = json.load(f)
            return jsonify(data)
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    # fallback sample data
    sample = [
        {"severity": "critical", "agent": "Ubuntu-Production-Target", "ip": "185.190.140.20", "event": "sshd: Authentication failed from IP", "timestamp": "2026-06-03T19:55:00Z"},
        {"severity": "low", "agent": "Test-Agent", "ip": "10.0.0.5", "event": "login success", "timestamp": "2026-06-03T19:55:05Z"}
    ]
    return jsonify(sample)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
