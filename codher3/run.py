import os
import random

from threading import Thread
from modules.packet_sniffer import start_sniffing, packet_logs

from werkzeug.utils import secure_filename
from flask import Flask, render_template, request, jsonify
from modules.encryption import encrypt_text, decrypt_text

from flask import send_file
from modules.packet_sniffer import export_pcap, protocol_counts

from modules.stegano_module import encode_message, decode_message


from modules.traffic_simulator import simulate_c2_traffic
from modules.ai_module import detect_anomalies, generate_analysis
import sqlite3, threading

# Start packet sniffing in the background thread only once
sniffer_thread = Thread(target=start_sniffing, daemon=True)
sniffer_thread.start()

app = Flask(__name__)

@app.route("/")
def home():
    return render_template("home.html")

@app.route("/realtime-monitoring")
def realtime_monitoring():
    return render_template("realtime_monitoring.html")

@app.route("/simulator")
def simulator():
    return render_template("simulator_menu.html")

UPLOAD_FOLDER = "static/uploaded/"
ENCODED_FOLDER = "static/encoded/"

@app.route("/steganography", methods=["GET", "POST"])
def steganography():
    result = ""
    image_url = None
    if request.method == "POST":
        if 'hide' in request.form:
            msg = request.form['message']
            uploaded_file = request.files['image']
            if uploaded_file.filename != '':
                filename = secure_filename(uploaded_file.filename)
                upload_path = os.path.join(UPLOAD_FOLDER, filename)
                uploaded_file.save(upload_path)

                output_path = os.path.join(ENCODED_FOLDER, f"encoded_{filename}")
                result = encode_message(upload_path, msg, output_path)
                image_url = output_path
        elif 'reveal' in request.form:
            uploaded_file = request.files['reveal_image']
            if uploaded_file.filename != '':
                filename = secure_filename(uploaded_file.filename)
                path = os.path.join(UPLOAD_FOLDER, filename)
                uploaded_file.save(path)
                result = decode_message(path)

    return render_template("steganography.html", result=result, image_url=image_url)

@app.route("/aes", methods=["GET", "POST"])
def aes():
    result = ""
    if request.method == "POST":
        text = request.form['text']
        if 'encrypt' in request.form:
            result = encrypt_text(text)
        elif 'decrypt' in request.form:
            result = decrypt_text(text)
    return render_template("aes_encryption.html", result=result)

@app.route("/analyser")
def analyser():
    ai_result = generate_analysis()
    return render_template("analyser.html", result=ai_result)

@app.route("/dynamic-graph")
def dynamic_graph():
    return render_template("dynamic_graph.html")

@app.route("/graph-data")
def graph_data():
    data = sniff_packets()
    return jsonify(data)

@app.route("/packet-analyser")
def packet_analyser():
    return render_template("packet_analyser.html")

@app.route("/c2-apps")
def c2_apps():
    return render_template("c2_apps.html")

@app.route("/network_monitoring")
def network_monitoring():
    return render_template("network_monitoring.html")

@app.route("/network_monitoring_logs")
def network_monitoring_logs():
    # Simulated data – replace with packet logs or ML analysis
    sample_data = [
        "10.0.0.1 > 10.0.0.5: Normal traffic",
        "192.168.1.2 > 8.8.8.8: DNS lookup",
        "Suspicious spike detected at 10.0.0.4",
        "Port scanning activity flagged from 172.16.0.7"
    ]
    return "\n".join(random.sample(sample_data, k=3))

@app.route("/intrusion_detection")
def intrusion_detection():
    return render_template("intrusion_detection.html")

@app.route("/intrusion_detection_status")
def intrusion_detection_status():
    alerts = [
        "<span style='color:green;'>System Secure: No intrusion detected</span>",
        "<span style='color:red;'>Alert: Multiple failed login attempts</span>",
        "<span style='color:orange;'>Warning: Abnormal packet rate observed</span>"
    ]
    return random.choice(alerts)

@app.route("/attack_response", methods=["GET", "POST"])
def attack_response():
    result = ""
    if request.method == "POST" and 'simulate' in request.form:
        result = "🛡️ Simulated firewall block triggered and system isolated from suspect IPs."
    return render_template("attack_response.html", result=result)

@app.route("/packet_analyser")
def packet_analyser():
    return render_template("packet_analyser.html")

@app.route("/packet_data")
def packet_data():
    return "<br>".join(packet_logs[-10:])  # Return last 10 packets

@app.route("/download_pcap")
def download_pcap():
    export_pcap()
    return send_file("static/pcap/captured.pcap", as_attachment=True)

@app.route("/protocol_counts")
def get_protocol_counts():
    return protocol_counts


def run_simulator():
    simulate_c2_traffic()

if __name__ == "__main__":
    threading.Thread(target=run_simulator).start()
    app.run(debug=True)
