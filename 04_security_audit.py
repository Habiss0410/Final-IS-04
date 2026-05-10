"""
04_security_audit_v2.py — Security Audit Report (Final)

Fixes:
  [1] VULN-002: files/token.txt 
  [2] VULN-003: Weak JWT Secret (OWASP M10)
  [3] Package: com.demo.mitm
  [4] Step 6 Compliance (GDPR + ISO 27002)
  [5] Step 7 Risk Assessment
  [6] Step 8 Evaluation + Demo order
  [7] HTML chuyên nghiệp: gradient header, cards, score bars

Cách chạy:
    export PYTHONPATH="python-tools"
    python python-tools/04_security_audit_v2.py
    -> Sinh file: reports/final_report.html
"""

import datetime
from pathlib import Path
from utils.logger import print_banner, log_info, log_success

APP_PACKAGE = "com.demo.mitm"

FINDINGS = [
    {
        "id": "VULN-001", "scenario": "Scenario 1", "cvss": "8.1", "severity": "CRITICAL",
        "title": "M3: Insecure Communication — User-installed CA Accepted",
        "description": "App trust toan bo CA bao gom User-installed CA. Ke tan cong cai Burp Suite CA vao AVD, cau hinh proxy 10.0.2.2:8080, doc credentials plaintext du HTTPS. Nan nhan khong phat hien vi HTTPS van hien thi.",
        "evidence": "Burp HTTP History: POST /api/login -> Body: {\"username\":\"admin\",\"password\":\"Secret@123\"} hien thi ro.",
        "fix": "Network Security Config: chi trust System CA + Certificate Pinning + block cleartext.",
        "owasp": "OWASP Mobile Top 10 — M3: Insecure Communication",
        "iso": "ISO/IEC 27002:2022 — §8.24, §8.26",
        "gdpr": "GDPR Article 32 — Data in transit",
    },
    {
        "id": "VULN-002", "scenario": "Scenario 2", "cvss": "7.4", "severity": "HIGH",
        "title": "M9: Insecure Data Storage — token.txt Plaintext",
        "description": f"App luu JWT session token vao /data/data/{APP_PACKAGE}/files/token.txt dang plaintext. Tren Android Emulator (mac dinh root), ke tan cong dung ADB shell doc truc tiep trong vai giay. Token lay duoc dung ngay de gia mao phien dang nhap.",
        "evidence": f"adb shell run-as {APP_PACKAGE} cat /data/data/{APP_PACKAGE}/files/token.txt -> eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4ifQ.secret123",
        "fix": "Xoa token.txt, luu token trong EncryptedSharedPreferences (AES-256-GCM) + Root Detection.",
        "owasp": "OWASP Mobile Top 10 — M9: Insecure Data Storage",
        "iso": "ISO/IEC 27002:2022 — §8.24, §8.10",
        "gdpr": "GDPR Article 32 — Data at rest",
    },
    {
        "id": "VULN-003", "scenario": "Scenario 2", "cvss": "7.5", "severity": "HIGH",
        "title": "M10: Insufficient Cryptography — Weak JWT Secret",
        "description": "Server ky JWT bang secret co dinh 'secret123' — nhan ra bang mat thuong khi decode token. Ke tan cong co the forge token tuy y voi payload bat ky, vi du: {\"user\":\"admin\",\"role\":\"superadmin\"}.",
        "evidence": "JWT decode: signature = 'secret123' doc duoc truc tiep tu token plaintext.",
        "fix": "server_hard.js dung crypto.randomBytes(32) — secret ngau nhien 256-bit, expiry 15 phut.",
        "owasp": "OWASP Mobile Top 10 — M10: Insufficient Cryptography",
        "iso": "ISO/IEC 27002:2022 — §8.24",
        "gdpr": "GDPR Article 32 — Security of processing",
    },
]

GDPR_COMPLIANCE = [
    {"article": "Article 5(1)(f)", "title": "Integrity & Confidentiality",
     "before": "Vi pham — credentials lo qua MITM; token luu plaintext",
     "after": "Tuan thu — TLS enforced + AES-256-GCM storage",
     "bp": False, "ap": True},
    {"article": "Article 25", "title": "Data Protection by Design",
     "before": "Vi pham — khong co co che bao ve mac dinh",
     "after": "Tuan thu — Certificate Pinning + EncryptedSharedPreferences tu dau",
     "bp": False, "ap": True},
    {"article": "Article 32", "title": "Security of Processing",
     "before": "Vi pham — khong ma hoa data in transit lan data at rest",
     "after": "Tuan thu — ca 2 lop duoc bao ve sau 2 scenario",
     "bp": False, "ap": True},
]

ISO_COMPLIANCE = [
    {"clause": "§8.24", "title": "Use of Cryptography", "scenario": "S1 + S2",
     "before": "TLS khong enforce; JWT secret yeu; storage khong ma hoa",
     "after": "TLS 1.2+ + AES-256-GCM + JWT secret 256-bit random",
     "bp": False, "ap": True},
    {"clause": "§8.26", "title": "Application Security Requirements", "scenario": "S1",
     "before": "App chap nhan User CA — khong kiem tra nguon goc certificate",
     "after": "Chi trust System CA; cleartext bi block; Certificate Pinning",
     "bp": False, "ap": True},
    {"clause": "§8.10", "title": "Information Deletion", "scenario": "S2",
     "before": "token.txt ton tai mai, khong xoa sau logout",
     "after": "Token xoa sau logout; EncryptedSharedPreferences quan ly lifecycle",
     "bp": False, "ap": True},
    {"clause": "§8.7", "title": "Protection Against Malware", "scenario": "S2",
     "before": "Khong phat hien thiet bi root — ADB khai thac tu do",
     "after": "Root Detection: app thoat khi phat hien /sbin/su hoac build test-keys",
     "bp": False, "ap": True},
]

RISKS = [
    {"id": "VULN-001", "scenario": "Scenario 1 — MITM",
     "threat": "Ke tan cong tren cung Wi-Fi cai Burp CA gia, chan HTTPS traffic",
     "vuln": "App trust User-installed CA — khong phan biet CA hop le va gia mao",
     "likelihood": "HIGH", "impact": "CRITICAL", "risk": "CRITICAL", "cvss": "8.1"},
    {"id": "VULN-002", "scenario": "Scenario 2 — Storage",
     "threat": "Ke tan cong co ADB access doc file token.txt trong vai giay",
     "vuln": "JWT token luu plaintext — khong can crack, doc truc tiep",
     "likelihood": "HIGH", "impact": "HIGH", "risk": "HIGH", "cvss": "7.4"},
    {"id": "VULN-003", "scenario": "Scenario 2 — Weak JWT",
     "threat": "Ke tan cong forge token voi payload tuy y (role: superadmin)",
     "vuln": "JWT secret 'secret123' — nhan ra bang mat thuong",
     "likelihood": "HIGH", "impact": "HIGH", "risk": "HIGH", "cvss": "7.5"},
]

EVALUATION = [
    {"c": "Bao ve credentials khi truyen mang", "b": "✗ Burp doc duoc username/password du HTTPS", "a": "✓ SSLHandshakeException — 0 byte bi intercept", "sb": "0/10", "sa": "9/10", "pct": 90},
    {"c": "Bao ve token luu tren thiet bi",      "b": "✗ ADB doc token.txt plaintext trong 3 giay", "a": "✓ token.txt khong con — AES-256-GCM", "sb": "0/10", "sa": "9/10", "pct": 90},
    {"c": "Do manh cua JWT secret",              "b": "✗ Secret co dinh 'secret123' — forge duoc", "a": "✓ crypto.randomBytes(32) — expiry 15 phut", "sb": "0/10", "sa": "10/10", "pct": 100},
    {"c": "Phat hien thiet bi bi xam pham",      "b": "✗ App chay binh thuong tren thiet bi root", "a": "✓ Root Detection — app thoat khi phat hien su", "sb": "0/10", "sa": "8/10", "pct": 80},
    {"c": "Tuan thu GDPR Article 32",            "b": "✗ Vi pham ca data in transit lan at rest", "a": "✓ Ca 2 lop duoc bao ve — dap ung day du", "sb": "0/10", "sa": "10/10", "pct": 100},
    {"c": "Tuan thu ISO 27002",                  "b": "✗ Vi pham §8.24, §8.26, §8.10, §8.7", "a": "✓ Dap ung du 4 dieu khoan lien quan", "sb": "0/10", "sa": "10/10", "pct": 100},
]

DEMO_STEPS = [
    ("01", "Khoi dong moi truong",
     "Mo Android Studio → start AVD Pixel 6 API 34 (ARM64)<br>Terminal: <code>cd dummy-server &amp;&amp; node server.js</code><br><b>Screenshot:</b> AVD running + [SERVER] HTTPS Listening on port 3000"),
    ("02", "S1 Phase 2.1: Attack (MITM)",
     "Burp Suite → Proxy Settings → Bind 127.0.0.1:8080<br>Export Burp CA → push AVD → cai cert → set proxy 10.0.2.2:8080<br>Mo app → dang nhap admin/Secret@123<br><b>Screenshot:</b> Burp HTTP History thay POST /api/login voi credentials ro"),
    ("03", "S1 Phase 2.2: Hardening",
     "Sua <code>network_security_config.xml</code> → trust System CA only + Certificate Pin<br>Rebuild (Shift+F10) → install lai len AVD<br><b>Screenshot:</b> file XML sau khi sua + build thanh cong"),
    ("04", "S1 Phase 2.3: Defense",
     "Giu nguyen Burp proxy → mo app → dang nhap lai<br><code>python python-tools/02_capture_traffic.py --phase hardened</code><br><b>Screenshot:</b> App bao loi SSL + Burp khong intercept duoc"),
    ("05", "S2 Phase 3.1: Attack (Storage)",
     "Dang nhap app → server.js tra token → app luu vao token.txt<br><code>python python-tools/03_storage_audit.py --phase attack</code><br><b>Screenshot:</b> Token plaintext + JWT decode + 200 OK tu /api/profile"),
    ("06", "S2 Phase 3.2: Hardening",
     "Chuyen sang <code>server_hard.js</code> → copy SHA-256 PIN → dien vao network_security_config.xml<br>Android branch android-hardened: EncryptedSharedPreferences + Root Detection<br><code>python python-tools/03_storage_audit.py --phase check</code><br><b>Screenshot:</b> Ket qua check hardening"),
    ("07", "S2 Phase 3.3: Defense",
     "<code>python python-tools/03_storage_audit.py --phase defense</code><br><b>Screenshot:</b> token.txt: No such file + 401 Unauthorized khi dung token cu"),
    ("08", "Sinh report tong hop",
     "<code>python python-tools/04_security_audit_v2.py</code><br>Mo <code>reports/final_report.html</code> trong trinh duyet<br><b>Screenshot:</b> Report HTML hien thi day du"),
]


def badge(text, color):
    return f'<span class="badge" style="background:{color}">{text}</span>'

def sev_badge(s):
    c = {"CRITICAL":"#dc2626","HIGH":"#ea580c","MEDIUM":"#ca8a04","LOW":"#16a34a"}
    return badge(s, c.get(s,"#64748b"))

def pass_badge(ok):
    return badge("✓ PASS","#16a34a") if ok else badge("✗ FAIL","#dc2626")

def lk_badge(l):
    c = {"HIGH":"#ea580c","MEDIUM":"#ca8a04","LOW":"#16a34a"}
    return badge(l, c.get(l,"#64748b"))


def generate_html_report(output_path):
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    finding_rows = ""
    for f in FINDINGS:
        finding_rows += f"""<tr>
          <td><code style="font-weight:bold">{f['id']}</code></td>
          <td><b>{f['scenario']}</b><br><small>{f['title']}</small></td>
          <td>{sev_badge(f['severity'])}<br><small>CVSS {f['cvss']}</small></td>
          <td><small>{f['description']}</small></td>
          <td><small style="color:#dc2626">{f['evidence']}</small></td>
          <td><small style="color:#16a34a">{f['fix']}</small></td>
          <td><small>{f['owasp']}</small></td>
          <td><small>{f['iso']}<br>{f['gdpr']}</small></td>
        </tr>"""

    gdpr_rows = ""
    for g in GDPR_COMPLIANCE:
        gdpr_rows += f"""<tr>
          <td><b>{g['article']}</b></td><td>{g['title']}</td>
          <td style="color:#dc2626"><small>{g['before']}</small></td>
          <td style="color:#16a34a"><small>{g['after']}</small></td>
          <td>{pass_badge(g['bp'])}</td><td>{pass_badge(g['ap'])}</td>
        </tr>"""

    iso_rows = ""
    for i in ISO_COMPLIANCE:
        iso_rows += f"""<tr>
          <td><b>{i['clause']}</b></td><td>{i['title']}</td><td><small>{i['scenario']}</small></td>
          <td style="color:#dc2626"><small>{i['before']}</small></td>
          <td style="color:#16a34a"><small>{i['after']}</small></td>
          <td>{pass_badge(i['bp'])}</td><td>{pass_badge(i['ap'])}</td>
        </tr>"""

    risk_rows = ""
    for r in RISKS:
        rc = {"CRITICAL":"#dc2626","HIGH":"#ea580c"}.get(r['risk'],"#64748b")
        risk_rows += f"""<tr>
          <td><code>{r['id']}</code></td><td><b>{r['scenario']}</b></td>
          <td><small>{r['threat']}</small></td><td><small>{r['vuln']}</small></td>
          <td>{lk_badge(r['likelihood'])}</td><td><small>{r['impact']}</small></td>
          <td>{badge(r['risk'],rc)}</td><td><b>{r['cvss']}</b></td>
        </tr>"""

    eval_rows = ""
    for e in EVALUATION:
        eval_rows += f"""<tr>
          <td>{e['c']}</td>
          <td style="color:#dc2626"><small>{e['b']}</small></td>
          <td style="color:#16a34a"><small>{e['a']}</small></td>
          <td style="text-align:center">{badge(e['sb'],'#dc2626')}</td>
          <td style="text-align:center">{badge(e['sa'],'#16a34a')}</td>
          <td><div style="background:#f1f5f9;border-radius:4px;height:8px;overflow:hidden">
            <div style="width:{e['pct']}%;height:100%;background:#16a34a;border-radius:4px"></div>
          </div></td>
        </tr>"""

    demo_rows = ""
    for num, title, detail in DEMO_STEPS:
        demo_rows += f"""<tr>
          <td style="text-align:center;font-weight:bold;color:#1d4ed8;font-size:20px">#{num}</td>
          <td><b>{title}</b></td>
          <td><small>{detail}</small></td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="vi">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Security Audit Report — Project 4</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Segoe UI',system-ui,sans-serif;background:#f8fafc;color:#1e293b;line-height:1.6;padding:0 16px 60px}}
.header{{background:linear-gradient(135deg,#0f172a 0%,#1e3a5f 100%);color:white;padding:40px 48px;margin:0 -16px 40px}}
.header h1{{font-size:28px;font-weight:700}}
.header .sub{{color:#94a3b8;font-size:14px;margin-top:6px}}
.header .badges{{margin-top:16px;display:flex;gap:8px;flex-wrap:wrap}}
.hbadge{{background:rgba(255,255,255,.1);border:1px solid rgba(255,255,255,.2);color:#e2e8f0;padding:3px 10px;border-radius:20px;font-size:12px}}
.container{{max-width:1100px;margin:0 auto}}
.toc{{background:white;border:1px solid #e2e8f0;border-radius:12px;padding:16px 24px;margin-bottom:24px;display:flex;flex-wrap:wrap;gap:6px 16px}}
.toc a{{color:#1d4ed8;text-decoration:none;font-size:13px}}
.toc a:hover{{text-decoration:underline}}
.toc-t{{font-weight:600;font-size:13px;width:100%;color:#475569}}
.section{{background:white;border-radius:12px;border:1px solid #e2e8f0;padding:28px 32px;margin-bottom:24px;box-shadow:0 1px 3px rgba(0,0,0,.04)}}
h2{{font-size:18px;font-weight:700;color:#0f172a;padding-bottom:12px;border-bottom:2px solid #e2e8f0;margin-bottom:20px;display:flex;align-items:center;gap:10px}}
.num{{background:#1d4ed8;color:white;width:28px;height:28px;border-radius:50%;display:inline-flex;align-items:center;justify-content:center;font-size:13px;flex-shrink:0}}
h3{{font-size:14px;font-weight:600;color:#1d4ed8;margin:20px 0 10px}}
.card-grid{{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin-bottom:20px}}
.card{{border-radius:10px;padding:16px 20px;border-left:4px solid}}
.card.red{{background:#fef2f2;border-color:#dc2626}}
.card.orange{{background:#fff7ed;border-color:#ea580c}}
.card.green{{background:#f0fdf4;border-color:#16a34a}}
.cl{{font-size:11px;text-transform:uppercase;letter-spacing:.5px;color:#64748b;font-weight:600}}
.cv{{font-size:22px;font-weight:700;margin:4px 0}}
.cs{{font-size:12px;color:#64748b}}
.box{{background:#f1f5f9;border-left:4px solid #1d4ed8;padding:14px 18px;border-radius:0 8px 8px 0;margin:12px 0;font-size:14px;line-height:1.7}}
.box.warn{{background:#fff7ed;border-color:#ea580c}}
.box.ok{{background:#f0fdf4;border-color:#16a34a}}
.tw{{overflow-x:auto;margin-top:12px;border-radius:8px;border:1px solid #e2e8f0}}
table{{width:100%;border-collapse:collapse;font-size:13px}}
th{{background:#1e293b;color:white;padding:10px 14px;text-align:left;font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:.3px;white-space:nowrap}}
td{{padding:10px 14px;border-bottom:1px solid #f1f5f9;vertical-align:top}}
tr:last-child td{{border-bottom:none}}
tr:hover td{{background:#f8fafc}}
.badge{{display:inline-block;padding:2px 9px;border-radius:20px;color:white;font-size:11px;font-weight:600;white-space:nowrap}}
code{{background:#f1f5f9;padding:1px 6px;border-radius:4px;font-family:'Consolas',monospace;font-size:12px;color:#0f172a}}
.footer{{text-align:center;color:#94a3b8;font-size:12px;margin-top:40px}}
@media print{{body{{background:white;padding:0}}.header{{margin:0}}.section{{box-shadow:none;break-inside:avoid}}}}
</style>
</head>
<body>
<div class="header">
  <div class="container">
    <h1>🔐 Security Audit Report</h1>
    <div class="sub">Project 4 — Android MITM Attack Lab &nbsp;|&nbsp; Generated: {now}</div>
    <div class="badges">
      <span class="hbadge">OWASP Mobile Top 10</span>
      <span class="hbadge">GDPR Article 32</span>
      <span class="hbadge">ISO/IEC 27002:2022</span>
      <span class="hbadge">Android API 34</span>
      <span class="hbadge">Package: {APP_PACKAGE}</span>
    </div>
  </div>
</div>
<div class="container">

<div class="toc">
  <div class="toc-t">📋 Muc luc</div>
  <a href="#s1">1. Executive Summary</a>
  <a href="#s2">2. Vulnerability Findings</a>
  <a href="#s3">3. Remediation</a>
  <a href="#s4">4. Attack Surface</a>
  <a href="#s5">5. Step 6 — Compliance</a>
  <a href="#s6">6. Step 7 — Risk Assessment</a>
  <a href="#s7">7. Step 8 — Evaluation</a>
  <a href="#s8">8. Demo Order</a>
  <a href="#s9">9. References</a>
</div>

<div class="section" id="s1">
  <h2><span class="num">1</span> Executive Summary</h2>
  <div class="card-grid">
    <div class="card red"><div class="cl">Vulnerabilities</div><div class="cv" style="color:#dc2626">3</div><div class="cs">1 CRITICAL · 2 HIGH</div></div>
    <div class="card orange"><div class="cl">Attack Scenarios</div><div class="cv" style="color:#ea580c">2</div><div class="cs">Network + Device Layer</div></div>
    <div class="card green"><div class="cl">Compliance After</div><div class="cv" style="color:#16a34a">7/7</div><div class="cs">GDPR + ISO 27002 PASS</div></div>
  </div>
  <div class="box">
    Project chung minh <strong>3 lo hong bao mat</strong> tren ung dung Android va server, bao gom ca lop <em>Network</em> va lop <em>Device Storage</em> — dap ung GDPR Article 32.<br><br>
    <strong>Scenario 1 — MITM (VULN-001):</strong> App trust User-installed CA → Burp intercept credentials → Fix: Network Security Config + Certificate Pinning.<br><br>
    <strong>Scenario 2 — Storage (VULN-002 + VULN-003):</strong> JWT plaintext trong <code>files/token.txt</code> + weak secret 'secret123' → ADB doc + forge token → Fix: EncryptedSharedPreferences + strong JWT + Root Detection.
  </div>
</div>

<div class="section" id="s2">
  <h2><span class="num">2</span> Vulnerability Findings &amp; Compliance Mapping</h2>
  <div class="tw"><table>
    <tr><th>ID</th><th>Scenario / Ten</th><th>Severity</th><th>Mo ta</th><th>Bang chung</th><th>Giai phap</th><th>OWASP</th><th>ISO / GDPR</th></tr>
    {finding_rows}
  </table></div>
</div>

<div class="section" id="s3">
  <h2><span class="num">3</span> Remediation</h2>
  <h3>3.1 Scenario 1 — Network Security Config + Certificate Pinning</h3>
  <div class="box">
    Ap dung <code>res/xml/network_security_config.xml</code>: <code>cleartextTrafficPermitted="false"</code>, chi trust <code>&lt;certificates src="system"/&gt;</code>, va Certificate Pinning voi SHA-256 pin tu <code>server_hard.js</code>.<br>
    Ket qua: App nem <code>SSLHandshakeException</code> — 0 byte bi intercept.
  </div>
  <h3>3.2 Scenario 2 — Secure Storage + Strong JWT + Root Detection</h3>
  <div class="box">
    <strong>(a)</strong> Xoa <code>token.txt</code>, luu token bang <code>EncryptedSharedPreferences</code> (AES-256-GCM, Android Keystore).<br>
    <strong>(b)</strong> <code>server_hard.js</code> dung <code>crypto.randomBytes(32)</code> thay secret co dinh — token expiry 15 phut.<br>
    <strong>(c)</strong> Root Detection: kiem tra <code>/sbin/su</code>, <code>Build.TAGS test-keys</code> → <code>finish()</code>.
  </div>
</div>

<div class="section" id="s4">
  <h2><span class="num">4</span> Attack Surface Comparison</h2>
  <div class="tw"><table>
    <tr><th>Tieu chi</th><th>Scenario 1 — MITM</th><th>Scenario 2 — Storage + Weak JWT</th></tr>
    <tr><td>Attack vector</td><td>Network (Wi-Fi proxy)</td><td>Local device (ADB shell)</td></tr>
    <tr><td>Dieu kien</td><td>Cung mang Wi-Fi voi nan nhan</td><td>ADB access hoac thiet bi bi mat</td></tr>
    <tr><td>Tool</td><td>Burp Suite Community (free)</td><td>ADB — co san trong Android SDK</td></tr>
    <tr><td>Du lieu bi lo</td><td>username + password in transit</td><td>JWT token at rest + forge tuy y</td></tr>
    <tr><td>OWASP</td><td>M3: Insecure Communication</td><td>M9: Insecure Storage + M10: Weak Crypto</td></tr>
    <tr><td>Fix — Server</td><td>TLS 1.2+ enforced</td><td>JWT secret random 256-bit + expiry 15p</td></tr>
    <tr><td>Fix — Android</td><td>Network Security Config + Pin</td><td>EncryptedSharedPreferences + Root Detection</td></tr>
    <tr><td>GDPR</td><td>Data in transit (Art.32)</td><td>Data at rest (Art.32)</td></tr>
  </table></div>
</div>

<div class="section" id="s5">
  <h2><span class="num">5</span> Step 6 — Compliance Evaluation</h2>
  <h3>5.1 GDPR — Bao ve du lieu ca nhan</h3>
  <div class="tw"><table>
    <tr><th>Dieu khoan</th><th>Noi dung</th><th>Truoc hardening</th><th>Sau hardening</th><th>Truoc</th><th>Sau</th></tr>
    {gdpr_rows}
  </table></div>
  <h3>5.2 ISO/IEC 27002:2022 — Endpoint Protection</h3>
  <div class="tw"><table>
    <tr><th>Dieu khoan</th><th>Ten</th><th>Scenario</th><th>Truoc hardening</th><th>Sau hardening</th><th>Truoc</th><th>Sau</th></tr>
    {iso_rows}
  </table></div>
  <div class="box ok" style="margin-top:16px">
    <strong>Ket luan:</strong> Truoc hardening vi pham toan bo 7 dieu khoan. Sau khi ap dung ca 2 scenario, tat ca 7 dieu khoan dat <strong>PASS</strong> — he thong tuan thu day du GDPR va ISO 27002.
  </div>
</div>

<div class="section" id="s6">
  <h2><span class="num">6</span> Step 7 — Risk Assessment</h2>
  <div class="tw"><table>
    <tr><th>ID</th><th>Scenario</th><th>Threat</th><th>Vulnerability</th><th>Likelihood</th><th>Impact</th><th>Risk</th><th>CVSS</th></tr>
    {risk_rows}
  </table></div>
  <div class="box warn" style="margin-top:16px">
    <strong>Overall Risk truoc hardening: 🔴 CRITICAL</strong><br>
    Ca 3 lo hong khai thac duoc bang free tools (Burp Suite, ADB) — khong can ky nang dac biet. Du lieu bi lo du de chiem toan bo tai khoan va forge token voi quyen bat ky.
  </div>
</div>

<div class="section" id="s7">
  <h2><span class="num">7</span> Step 8 — Evaluation</h2>
  <h3>7.1 Muc do bao mat truoc va sau hardening</h3>
  <div class="tw"><table>
    <tr><th>Tieu chi</th><th>Truoc hardening</th><th>Sau hardening</th><th>Diem truoc</th><th>Diem sau</th><th style="width:120px">Progress</th></tr>
    {eval_rows}
  </table></div>
  <h3>7.2 Nhan xet he thong</h3>
  <div class="box ok">
    <strong>✅ Diem manh sau hardening</strong><br>
    He thong bao ve duoc ca 2 vector tan cong: network layer va device layer.
    Ket hop Network Security Config + Certificate Pinning + EncryptedSharedPreferences + Strong JWT + Root Detection tao thanh <strong>5 lop phong thu doc lap</strong>.
  </div>
  <div class="box warn">
    <strong>⚠️ Han che con ton tai</strong><br>
    Root Detection file-based co the bi bypass boi Magisk Hide. Production nen them <strong>Play Integrity API</strong>. Certificate Pinning can quy trinh rotation khi cert het han.
  </div>
  <div class="box">
    <strong>📋 Nhan xet tong the</strong><br>
    App truoc hardening: <strong>0/10</strong> o moi tieu chi, vi pham OWASP M3/M9/M10, khong dap ung GDPR Article 32.<br>
    Sau hardening: trung binh <strong>9.3/10</strong>, dap ung day du GDPR va ISO 27002.
    Day la minh chung ro rang cho nguyen tac <em>Security by Design</em>.
  </div>
</div>

<div class="section" id="s8">
  <h2><span class="num">8</span> Thu tu Demo &amp; Screenshot can chup</h2>
  <div class="box" style="margin-bottom:16px">
    Chay tuan tu theo bang. Moi buoc ghi ro lenh va <strong>screenshot can chup</strong> lam bang chung nop bai.<br><br>
    <strong>Quick commands (Mac/Linux):</strong><br>
    <code>export PYTHONPATH="python-tools"</code> &nbsp;|&nbsp;
    <code>node dummy-server/server.js</code> &nbsp;→&nbsp;
    <code>node dummy-server/server_hard.js</code>
  </div>
  <div class="tw"><table>
    <tr><th style="width:60px">Buoc</th><th style="width:200px">Ten</th><th>Chi tiet &amp; Screenshot</th></tr>
    {demo_rows}
  </table></div>
</div>

<div class="section" id="s9">
  <h2><span class="num">9</span> References</h2>
  <ul style="padding-left:20px;line-height:2.2">
    <li>OWASP Mobile Security Testing Guide (MSTG) 2024</li>
    <li>OWASP Mobile Top 10 — M3: Insecure Communication, M9: Insecure Data Storage, M10: Insufficient Cryptography</li>
    <li>ISO/IEC 27002:2022 — §8.7, §8.10, §8.24, §8.26</li>
    <li>GDPR Regulation (EU) 2016/679 — Article 5, 25, 32</li>
    <li>Android Developer Docs: Network Security Configuration</li>
    <li>Android Developer Docs: EncryptedSharedPreferences (AndroidX Security Crypto)</li>
    <li>Android Keystore System Documentation</li>
    <li>PortSwigger: Installing Burp CA Certificate on Android</li>
    <li>RFC 7519 — JSON Web Token (JWT)</li>
  </ul>
</div>

<div class="footer">Project 4 — Android MITM Security Lab &nbsp;|&nbsp; Generated by 04_security_audit_v2.py &nbsp;|&nbsp; {now}</div>
</div>
</body>
</html>"""

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
    log_success(f"Bao cao da duoc luu: {output_path}")


def main():
    print_banner("SECURITY AUDIT REPORT — Project 4 (Final)")
    output = "reports/final_report.html"
    log_info(f"Dang sinh bao cao → {output}")
    generate_html_report(output)
    log_success("Xong! Mo reports/final_report.html trong trinh duyet.")


if __name__ == "__main__":
    main()
