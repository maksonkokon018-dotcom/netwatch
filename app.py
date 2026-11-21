"""Точка входу: веб-сервер Flask. Запуск: python app.py"""
import csv
import io
import threading
from urllib.parse import urlparse

from flask import Flask, Response, abort, jsonify, redirect, render_template_string, request

import scanner
import tools
from templates import DEVICE_HTML, HISTORY_HTML, INDEX_HTML, TOOLS_HTML

app = Flask(__name__)


@app.before_request
def guard():
    """Захист: лише localhost і без запитів з чужих сайтів."""
    if request.host.split(":")[0] not in ("127.0.0.1", "localhost"):
        abort(403)
    if request.method == "POST":
        origin = request.headers.get("Origin")
        if origin and urlparse(origin).netloc != request.host:
            abort(403)


def start_scan():
    threading.Thread(target=scanner.scan_network, daemon=True).start()


@app.route("/")
def index():
    s = scanner.state
    return render_template_string(
        INDEX_HTML,
        devices=s.sorted_devices(),
        scanning=s.scanning,
        stage=s.stage,
        network=s.network,
        local_ip=s.local_ip,
        last_scan=s.last_scan,
    )


@app.route("/device/<ip>")
def device(ip):
    d = scanner.state.get(ip)
    if d is None:
        abort(404)
    return render_template_string(DEVICE_HTML, d=d)


@app.route("/device/<ip>/label", methods=["POST"])
def device_label(ip):
    if not scanner.set_label(ip, request.form.get("label", "")):
        abort(404)
    return redirect("/device/" + ip)


@app.route("/rescan", methods=["POST"])
def rescan():
    if not scanner.state.scanning:
        start_scan()
    return redirect("/")


@app.route("/tools")
def tools_page():
    return render_template_string(TOOLS_HTML, tools=tools.TOOLS)


@app.route("/history")
def history_page():
    return render_template_string(HISTORY_HTML, rows=scanner.history_rows())


@app.route("/api/<name>", methods=["POST"])
def api(name):
    tool = tools.TOOLS_BY_ID.get(name)
    if tool is None:
        abort(404)
    try:
        return jsonify(tool["run"](request.form))
    except tools.ToolError as e:
        return jsonify(error=str(e)), 400
    except Exception as e:  # щоб сервер не падав через помилку інструмента
        return jsonify(error="Внутрішня помилка: %s" % e), 500


@app.route("/export.json")
def export_json():
    return jsonify(scanner.state.sorted_devices())


@app.route("/export.csv")
def export_csv():
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["ip", "mac", "hostname", "label", "vendor", "type", "open_ports", "first_seen", "last_seen"])
    for d in scanner.state.sorted_devices():
        w.writerow([d["ip"], d["mac"], d["hostname"], d.get("label", ""), d["vendor"], d["type"],
                    ";".join(str(p["port"]) for p in d["ports"]), d.get("first_seen", ""), d["seen"]])
    data = "\ufeff" + buf.getvalue()  # BOM, щоб Excel правильно показав кирилицю
    return Response(data, mimetype="text/csv; charset=utf-8",
                    headers={"Content-Disposition": "attachment; filename=devices.csv"})


if __name__ == "__main__":
    start_scan()
    print("Відкрий у браузері: http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, debug=False)
