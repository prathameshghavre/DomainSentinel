"""app.py - Flask dashboard for the OSINT tool."""

import csv
import io
import json

from flask import Flask, Response, abort, redirect, render_template, request, url_for

from osint.database import get_history, get_scan, init_db, save_scan
from osint.scanner import scan_domain

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024  # reject unusually large requests

init_db()


@app.after_request
def add_security_headers(response):
    """Basic hardening headers added to every response."""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self' 'unsafe-inline'"
    )
    return response


@app.route("/")
def index():
    return render_template("index.html", history=get_history(20), error=None)


@app.route("/scan", methods=["POST"])
def scan():
    report = scan_domain(request.form.get("domain", ""))
    if not report["ok"]:
        return (
            render_template(
                "index.html", history=get_history(20), error=report["error"]
            ),
            400,
        )
    scan_id = save_scan(report)
    return redirect(url_for("view_scan", scan_id=scan_id))


@app.route("/scan/<int:scan_id>")
def view_scan(scan_id):
    report = get_scan(scan_id)
    if report is None:
        abort(404)
    return render_template("report.html", report=report, scan_id=scan_id)


@app.route("/scan/<int:scan_id>/export.json")
def export_scan_json(scan_id):
    report = get_scan(scan_id)
    if report is None:
        abort(404)
    return Response(
        json.dumps(report, indent=2),
        mimetype="application/json",
        headers={"Content-Disposition": f"attachment; filename=scan_{scan_id}.json"},
    )


@app.route("/history.csv")
def export_history_csv():
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["id", "scanned_at_utc", "domain", "score", "severity", "data_complete"])
    for row in get_history(1000):
        writer.writerow([row["id"], row["scanned_at"], row["domain"],
                         row["score"], row["severity"], row["data_complete"]])
    return Response(
        buffer.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=scan_history.csv"},
    )


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)