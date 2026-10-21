from osint.database import init_db, save_scan, get_history
from osint.scanner import scan_domain

init_db()

tests = ["google.com", "example.com", "http://bad input",
         "this-domain-should-not-exist-98765.com"]

for name in tests:
    report = scan_domain(name)
    if not report["ok"]:
        print("REJECTED:", repr(name), "->", report["error"])
        continue
    scan_id = save_scan(report)
    risk = report["risk"]
    print("Saved scan", scan_id, "|", report["domain"],
          "| score", risk["score"], risk["severity"])

print("\n== History ==")
for row in get_history():
    print(row)