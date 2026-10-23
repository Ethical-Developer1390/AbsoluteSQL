"""
AbsoluteSQL — Reporter
Generates JSON and HTML reports from scan and extraction results.
"""

import json
import os
from datetime import datetime
from typing import Optional, List

from .config import VERSION, CODENAME, REPORTS_DIR
from .scanner import ScanResult, Vulnerability
from .extractor import ExtractionResult, DBInfo, TableInfo
from .utils import make_report_filename, truncate


class Reporter:
    """
    Builds structured reports from ScanResult + ExtractionResult data.
    """

    def __init__(
        self,
        scan:       ScanResult,
        extraction: Optional[ExtractionResult] = None,
    ) -> None:
        self.scan       = scan
        self.extraction = extraction
        self.ts         = datetime.now().isoformat()

    # ── JSON ──────────────────────────────────────────────────────────────────
    def to_dict(self) -> dict:
        vuln_list = []
        for v in self.scan.vulns:
            vuln_list.append({
                "param":       v.param,
                "method":      v.method,
                "type":        v.label(),
                "type_id":     v.inj_type,
                "payload":     v.payload,
                "dbms":        v.dbms,
                "confidence":  round(v.confidence, 3),
                "union_cols":  v.union_cols,
                "union_idx":   v.union_idx,
                "evidence":    v.evidence,
            })

        report = {
            "tool":           f"AbsoluteSQL v{VERSION} ({CODENAME})",
            "timestamp":      self.ts,
            "target":         self.scan.url,
            "method":         self.scan.method,
            "waf":            self.scan.waf,
            "dbms":           self.scan.dbms,
            "params_tested":  self.scan.params_tested,
            "requests_sent":  self.scan.requests_sent,
            "elapsed_s":      round(self.scan.elapsed, 2),
            "vulnerable":     self.scan.vulnerable,
            "vulnerabilities": vuln_list,
            "extraction":     None,
        }

        if self.extraction:
            ext_dbs = []
            for db in self.extraction.databases:
                ext_tables = []
                for tbl in db.tables:
                    ext_tables.append({
                        "name":      tbl.name,
                        "row_count": tbl.row_count,
                        "columns":   tbl.columns,
                        "rows":      tbl.rows[:50],  # cap rows in JSON
                    })
                ext_dbs.append({"name": db.name, "tables": ext_tables})

            report["extraction"] = {
                "dbms":         self.extraction.dbms,
                "version":      self.extraction.version,
                "current_user": self.extraction.current_user,
                "current_db":   self.extraction.current_db,
                "hostname":     self.extraction.hostname,
                "databases":    ext_dbs,
            }

        return report

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False, default=str)

    def save_json(self, path: Optional[str] = None) -> str:
        path = path or make_report_filename(self.scan.url, "json")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(self.to_json())
        return path

    # ── HTML ──────────────────────────────────────────────────────────────────
    def to_html(self) -> str:
        d      = self.to_dict()
        vulns  = d["vulnerabilities"]
        ext    = d["extraction"]
        status = "VULNERABLE" if d["vulnerable"] else "CLEAN"
        status_color = "#ff4444" if d["vulnerable"] else "#44ff88"
        vuln_count = len(vulns)

        vuln_rows = ""
        for v in vulns:
            conf_pct = int(v["confidence"] * 100)
            conf_color = "#ff4444" if conf_pct >= 90 else "#ffaa44"
            vuln_rows += f"""
            <tr>
              <td><code class="param">{v["param"]}</code></td>
              <td><span class="badge badge-type">{v["type"]}</span></td>
              <td>{v["method"]}</td>
              <td>{v["dbms"] or "Unknown"}</td>
              <td><div class="conf-bar" style="--pct:{conf_pct}%;--clr:{conf_color}">
                <span>{conf_pct}%</span></div></td>
              <td class="evidence">{truncate(v["evidence"], 80)}</td>
            </tr>"""

        db_sections = ""
        if ext and ext.get("databases"):
            for db in ext["databases"]:
                table_sections = ""
                for tbl in db.get("tables", []):
                    col_headers = "".join(f"<th>{c}</th>" for c in tbl["columns"])
                    row_html = ""
                    for row in tbl.get("rows", []):
                        cells = "".join(
                            f"<td>{truncate(str(row.get(c, '')), 60)}</td>"
                            for c in tbl["columns"]
                        )
                        row_html += f"<tr>{cells}</tr>"

                    rc = tbl.get("row_count")
                    rc_badge = f'<span class="badge badge-rows">{rc} rows</span>' if rc else ""
                    table_sections += f"""
                    <div class="table-block">
                      <div class="table-header">
                        <span class="table-icon">⊞</span>
                        <strong>{tbl["name"]}</strong>
                        {rc_badge}
                        <span class="cols-badge">{len(tbl["columns"])} cols</span>
                      </div>
                      <div class="table-scroll">
                        <table class="data-table">
                          <thead><tr>{col_headers}</tr></thead>
                          <tbody>{row_html or "<tr><td colspan='99' class='no-data'>No rows dumped</td></tr>"}</tbody>
                        </table>
                      </div>
                    </div>"""

                db_sections += f"""
                <div class="db-block">
                  <div class="db-header">
                    <span class="db-icon">🗄</span>
                    <strong>{db["name"]}</strong>
                    <span class="badge badge-tables">{len(db.get("tables", []))} tables</span>
                  </div>
                  {table_sections or "<p class='no-data'>No tables extracted</p>"}
                </div>"""

        ext_meta = ""
        if ext:
            rows = [
                ("DBMS",         ext.get("dbms")         or "—"),
                ("Version",      ext.get("version")      or "—"),
                ("Current User", ext.get("current_user") or "—"),
                ("Current DB",   ext.get("current_db")   or "—"),
                ("Hostname",     ext.get("hostname")      or "—"),
            ]
            cells = "".join(f"""
              <div class="meta-card">
                <div class="meta-label">{label}</div>
                <div class="meta-value">{val}</div>
              </div>""" for label, val in rows)
            ext_meta = f'<div class="meta-grid">{cells}</div>'

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>AbsoluteSQL — Scan Report</title>
  <style>
    :root {{
      --bg:       #0a0a0f;
      --bg2:      #111118;
      --bg3:      #1a1a24;
      --border:   #2a2a3a;
      --accent:   #ff4444;
      --accent2:  #ff6b35;
      --green:    #44ff88;
      --cyan:     #00d4ff;
      --yellow:   #ffd700;
      --text:     #e8e8f0;
      --muted:    #6a6a8a;
      --font:     'Courier New', monospace;
      --radius:   6px;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      background: var(--bg);
      color: var(--text);
      font-family: var(--font);
      font-size: 13px;
      line-height: 1.6;
    }}
    .header {{
      background: linear-gradient(135deg, #0d0d1a 0%, #1a0a1a 50%, #0a1a0a 100%);
      border-bottom: 1px solid var(--border);
      padding: 32px 40px;
      position: relative;
      overflow: hidden;
    }}
    .header::before {{
      content: '';
      position: absolute;
      top: 0; left: 0; right: 0; bottom: 0;
      background: repeating-linear-gradient(
        0deg, transparent, transparent 30px,
        rgba(255,68,68,0.03) 30px, rgba(255,68,68,0.03) 31px
      );
    }}
    .logo {{
      font-size: 28px;
      font-weight: bold;
      letter-spacing: 4px;
      color: var(--accent);
      text-shadow: 0 0 20px rgba(255,68,68,0.5);
      position: relative;
    }}
    .logo span {{ color: var(--accent2); }}
    .subtitle {{
      color: var(--muted);
      font-size: 11px;
      letter-spacing: 2px;
      margin-top: 4px;
      position: relative;
    }}
    .status-banner {{
      display: inline-block;
      padding: 6px 20px;
      border-radius: 3px;
      font-size: 14px;
      font-weight: bold;
      letter-spacing: 3px;
      margin-top: 16px;
      border: 1px solid;
      color: {status_color};
      border-color: {status_color};
      background: {status_color}11;
      position: relative;
    }}
    .container {{ max-width: 1400px; margin: 0 auto; padding: 32px 40px; }}
    .section {{ margin-bottom: 40px; }}
    .section-title {{
      font-size: 11px;
      letter-spacing: 3px;
      color: var(--muted);
      text-transform: uppercase;
      border-bottom: 1px solid var(--border);
      padding-bottom: 8px;
      margin-bottom: 20px;
    }}
    .section-title span {{ color: var(--accent); }}
    .info-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
      gap: 12px;
    }}
    .info-card {{
      background: var(--bg2);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      padding: 16px;
    }}
    .info-label {{
      font-size: 10px;
      letter-spacing: 2px;
      color: var(--muted);
      text-transform: uppercase;
      margin-bottom: 6px;
    }}
    .info-value {{
      color: var(--cyan);
      word-break: break-all;
      font-size: 13px;
    }}
    .vuln-table, .data-table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 12px;
    }}
    .vuln-table th, .data-table th {{
      text-align: left;
      padding: 10px 14px;
      background: var(--bg3);
      border: 1px solid var(--border);
      color: var(--muted);
      font-size: 10px;
      letter-spacing: 2px;
      text-transform: uppercase;
    }}
    .vuln-table td, .data-table td {{
      padding: 10px 14px;
      border: 1px solid var(--border);
      vertical-align: top;
    }}
    .vuln-table tr:hover td {{ background: var(--bg3); }}
    code.param {{
      background: rgba(0,212,255,0.1);
      color: var(--cyan);
      padding: 2px 8px;
      border-radius: 3px;
      border: 1px solid rgba(0,212,255,0.2);
    }}
    .badge {{
      display: inline-block;
      padding: 2px 10px;
      border-radius: 3px;
      font-size: 10px;
      letter-spacing: 1px;
      font-weight: bold;
    }}
    .badge-type   {{ background: rgba(255,68,68,0.15); color: var(--accent); border: 1px solid rgba(255,68,68,0.3); }}
    .badge-rows   {{ background: rgba(255,215,0,0.1); color: var(--yellow); border: 1px solid rgba(255,215,0,0.2); margin-left: 8px; }}
    .badge-tables {{ background: rgba(68,255,136,0.1); color: var(--green); border: 1px solid rgba(68,255,136,0.2); margin-left: 8px; }}
    .cols-badge   {{ background: rgba(0,212,255,0.1); color: var(--cyan); border: 1px solid rgba(0,212,255,0.2); margin-left: 8px;
                     display: inline-block; padding: 2px 8px; border-radius: 3px; font-size: 10px; }}
    .conf-bar {{
      position: relative;
      background: var(--bg3);
      border-radius: 3px;
      height: 20px;
      min-width: 80px;
      overflow: hidden;
    }}
    .conf-bar::before {{
      content: '';
      position: absolute;
      left: 0; top: 0; bottom: 0;
      width: var(--pct);
      background: var(--clr);
      opacity: 0.3;
    }}
    .conf-bar span {{
      position: relative;
      z-index: 1;
      padding: 0 8px;
      line-height: 20px;
      font-size: 11px;
    }}
    .evidence {{ color: var(--muted); font-size: 11px; max-width: 300px; }}
    .db-block {{
      background: var(--bg2);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      margin-bottom: 20px;
      overflow: hidden;
    }}
    .db-header {{
      padding: 14px 18px;
      background: var(--bg3);
      border-bottom: 1px solid var(--border);
      display: flex;
      align-items: center;
      gap: 8px;
    }}
    .db-icon {{ font-size: 16px; }}
    .table-block {{ margin: 16px; margin-top: 0; }}
    .table-block:first-child {{ margin-top: 16px; }}
    .table-header {{
      padding: 10px 14px;
      background: rgba(255,68,68,0.05);
      border: 1px solid var(--border);
      border-bottom: none;
      border-radius: var(--radius) var(--radius) 0 0;
      display: flex;
      align-items: center;
      gap: 4px;
    }}
    .table-icon {{ color: var(--accent); margin-right: 6px; }}
    .table-scroll {{ overflow-x: auto; }}
    .table-scroll .data-table {{
      border-radius: 0 0 var(--radius) var(--radius);
    }}
    .meta-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
      gap: 12px;
      margin-bottom: 24px;
    }}
    .meta-card {{
      background: var(--bg2);
      border: 1px solid var(--border);
      border-left: 3px solid var(--accent);
      border-radius: var(--radius);
      padding: 12px 16px;
    }}
    .meta-label {{
      font-size: 9px;
      letter-spacing: 2px;
      color: var(--muted);
      text-transform: uppercase;
      margin-bottom: 4px;
    }}
    .meta-value {{
      color: var(--green);
      font-size: 12px;
      word-break: break-all;
    }}
    .no-data {{ color: var(--muted); font-style: italic; text-align: center; padding: 16px !important; }}
    .footer {{
      border-top: 1px solid var(--border);
      padding: 20px 40px;
      color: var(--muted);
      font-size: 10px;
      letter-spacing: 1px;
      display: flex;
      justify-content: space-between;
    }}
    .stat-row {{
      display: flex;
      gap: 24px;
      margin-bottom: 20px;
    }}
    .stat-box {{
      background: var(--bg2);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      padding: 16px 24px;
      text-align: center;
      flex: 1;
    }}
    .stat-num {{
      font-size: 28px;
      font-weight: bold;
      color: var(--accent);
    }}
    .stat-label {{
      font-size: 9px;
      letter-spacing: 2px;
      color: var(--muted);
      text-transform: uppercase;
      margin-top: 4px;
    }}
    .no-vulns {{
      background: var(--bg2);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      padding: 32px;
      text-align: center;
      color: var(--green);
    }}
  </style>
</head>
<body>

<div class="header">
  <div class="logo">ABSOLUTE<span>SQL</span></div>
  <div class="subtitle">SQL INJECTION TESTING PLATFORM — v{VERSION} ({CODENAME})</div>
  <div class="status-banner">● {status} — {vuln_count} INJECTION POINT{"S" if vuln_count != 1 else ""} FOUND</div>
</div>

<div class="container">

  <!-- Scan Info -->
  <div class="section">
    <div class="section-title"><span>01</span> SCAN INFORMATION</div>
    <div class="info-grid">
      <div class="info-card">
        <div class="info-label">Target URL</div>
        <div class="info-value">{d["target"]}</div>
      </div>
      <div class="info-card">
        <div class="info-label">Method</div>
        <div class="info-value">{d["method"]}</div>
      </div>
      <div class="info-card">
        <div class="info-label">WAF Detected</div>
        <div class="info-value">{d["waf"] or "None"}</div>
      </div>
      <div class="info-card">
        <div class="info-label">DBMS</div>
        <div class="info-value">{d["dbms"] or "Unknown"}</div>
      </div>
      <div class="info-card">
        <div class="info-label">Timestamp</div>
        <div class="info-value">{d["timestamp"]}</div>
      </div>
      <div class="info-card">
        <div class="info-label">Parameters Tested</div>
        <div class="info-value">{", ".join(d["params_tested"]) or "—"}</div>
      </div>
    </div>
  </div>

  <!-- Stats -->
  <div class="stat-row">
    <div class="stat-box">
      <div class="stat-num">{vuln_count}</div>
      <div class="stat-label">Vulnerabilities</div>
    </div>
    <div class="stat-box">
      <div class="stat-num">{d["requests_sent"]}</div>
      <div class="stat-label">Requests Sent</div>
    </div>
    <div class="stat-box">
      <div class="stat-num">{d["elapsed_s"]}s</div>
      <div class="stat-label">Elapsed Time</div>
    </div>
    <div class="stat-box">
      <div class="stat-num">{len(d["params_tested"])}</div>
      <div class="stat-label">Params Tested</div>
    </div>
  </div>

  <!-- Vulnerabilities -->
  <div class="section">
    <div class="section-title"><span>02</span> VULNERABILITIES</div>
    {"<table class='vuln-table'><thead><tr><th>Parameter</th><th>Type</th><th>Method</th><th>DBMS</th><th>Confidence</th><th>Evidence</th></tr></thead><tbody>" + vuln_rows + "</tbody></table>" if vulns else "<div class='no-vulns'>✔ No SQL injection vulnerabilities detected</div>"}
  </div>

  <!-- Extraction Results -->
  {"<div class='section'><div class='section-title'><span>03</span> EXTRACTED DATA</div>" + ext_meta + db_sections + "</div>" if ext else ""}

</div>

<div class="footer">
  <span>AbsoluteSQL v{VERSION} ({CODENAME})</span>
  <span>Generated {self.ts}</span>
  <span>For authorized testing only</span>
</div>

</body>
</html>"""

    def save_html(self, path: Optional[str] = None) -> str:
        path = path or make_report_filename(self.scan.url, "html")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(self.to_html())
        return path

    def save(self, fmt: str = "both", base_path: Optional[str] = None) -> List[str]:
        """Save report(s) in specified format. Returns list of saved paths."""
        saved = []
        if fmt in ("json", "both"):
            p = base_path + ".json" if base_path else None
            saved.append(self.save_json(p))
        if fmt in ("html", "both"):
            p = base_path + ".html" if base_path else None
            saved.append(self.save_html(p))
        return saved
