"""app.py - Flask dashboard for DomainSentinel."""

import csv
import io
import json
from concurrent.futures import ThreadPoolExecutor

from flask import Flask, Response, abort, redirect, render_template, request, url_for

from osint.database import get_history, get_scan, get_stats, init_db, save_scan
from osint.extractor import analyze_headers, extract_domains
from osint.scanner import scan_domain

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 128 * 1024  # pasted emails can be long, but are limited

SEVERITY_ORDER = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}
MAX_TEXT_CHARS = 50000
SCAN_WORKERS = 4

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


def _dashboard(error=None):
    return render_template("index.html", stats=get_stats(),
                           history=get_history(8), error=error,
                           active="dashboard")


@app.route("/")
def index():
    return _dashboard()


@app.route("/scan", methods=["POST"])
def scan():
    report = scan_domain(request.form.get("domain", ""))
    if not report["ok"]:
        return _dashboard(error=report["error"]), 400
    scan_id = save_scan(report)
    return redirect(url_for("view_scan", scan_id=scan_id))


@app.route("/triage", methods=["GET", "POST"])
def triage():
    if request.method == "GET":
        return render_template("triage.html", active="triage",
                               result=None, text="", error=None)

    text = request.form.get("text", "")[:MAX_TEXT_CHARS]
    extracted = extract_domains(text)
    if not extracted["domains"]:
        return render_template(
            "triage.html", active="triage", result=None, text=text,
            error="No domain names were found in this text."), 400

    # Network lookups run in parallel; database writes stay in this thread.
    names = [item["domain"] for item in extracted["domains"]]
    with ThreadPoolExecutor(max_workers=SCAN_WORKERS) as pool:
        reports = list(pool.map(scan_domain, names))

    rows = []
    for item, report in zip(extracted["domains"], reports):
        if not report["ok"]:
            continue
        findings = sorted(report["risk"]["findings"],
                          key=lambda f: f["points"], reverse=True)
        rows.append({
            "domain": item["domain"],
            "sources": item["sources"],
            "score": report["risk"]["score"],
            "severity": report["risk"]["severity"],
            "reason": findings[0]["factor"] if findings else "No warning signs found",
            "complete": report["risk"]["data_complete"],
            "scan_id": save_scan(report),
        })
    rows.sort(key=lambda r: r["score"], reverse=True)

    result = {
        "rows": rows,
        "high": sum(1 for r in rows if r["severity"] in ("High", "Critical")),
        "worst": max((r["severity"] for r in rows),
                     key=lambda s: SEVERITY_ORDER[s], default="Low"),
        "truncated": extracted["truncated"],
        "headers": analyze_headers(text),
    }
    return render_template("triage.html", active="triage", result=result,
                           text=text, error=None)


@app.route("/scan/<int:scan_id>")
def view_scan(scan_id):
    report = get_scan(scan_id)
    if report is None:
        abort(404)
    return render_template("report.html", report=report, scan_id=scan_id,
                           active="history")


@app.route("/history")
def history_page():
    severity = request.args.get("severity", "")
    query = request.args.get("q", "").strip()[:100]
    rows = get_history(200, severity or None, query or None)
    return render_template("history.html", rows=rows, severity=severity,
                           q=query, active="history")


@app.route("/about")
def about():
    return render_template("about.html", active="about")


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