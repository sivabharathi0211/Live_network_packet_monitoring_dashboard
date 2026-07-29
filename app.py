from flask import Flask, jsonify, render_template, request

from device_scanner import DeviceScanner
from packet_monitor import PacketMonitor


app = Flask(__name__)
monitor = PacketMonitor(max_packets=1000)
scanner = DeviceScanner()


@app.route("/")
def dashboard():
    return render_template("index.html")


@app.route("/api/status")
def status():
    return jsonify(monitor.get_status())


@app.route("/api/start", methods=["POST"])
def start_capture():
    interface = request.json.get("interface") if request.is_json else None
    result = monitor.start(interface=interface)
    return jsonify(result), 200 if result["ok"] else 400


@app.route("/api/stop", methods=["POST"])
def stop_capture():
    return jsonify(monitor.stop())


@app.route("/api/packets")
def packets():
    filters = {
        "ip": request.args.get("ip", "").strip(),
        "protocol": request.args.get("protocol", "").strip(),
        "port": request.args.get("port", "").strip(),
        "service": request.args.get("service", "").strip(),
    }
    limit = request.args.get("limit", "300")
    return jsonify(monitor.get_packets(filters=filters, limit=limit))


@app.route("/api/stats")
def stats():
    return jsonify(monitor.get_statistics())


@app.route("/api/devices")
def devices():
    refresh = request.args.get("refresh", "false").lower() == "true"
    return jsonify(scanner.get_devices(refresh=refresh))


@app.route("/api/interfaces")
def interfaces():
    return jsonify(monitor.get_interfaces())


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True, threaded=True)
