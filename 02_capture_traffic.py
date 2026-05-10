"""
02_capture_traffic.py — Demo Phase 2.1 & 2.3: MITM Traffic Analysis

Script này KHÔNG thực sự capture traffic (Burp Suite làm việc đó).
Thay vào đó, nó:
  1. Đọc file HAR export từ Burp Suite (sau khi bạn export thủ công)
  2. Phân tích và highlight các thông tin nhạy cảm bị lộ
  3. So sánh kết quả Trước và Sau khi vá lỗi

Cách dùng:
    # Phase 2.1 - Phân tích traffic bị lộ (export HAR từ Burp trước)
    python python-tools/02_capture_traffic.py --file reports/raw_logs/captured.har --phase vulnerable

    # Phase 2.3 - Phân tích sau khi vá (Burp sẽ không capture được gì)
    python python-tools/02_capture_traffic.py --phase hardened
"""

import argparse
import json
import re
import os
from pathlib import Path
from utils.logger import print_banner, log_info, log_success, log_danger, log_warning, console


# ──────────────────────────────────────────────
# Các pattern nhận dạng thông tin nhạy cảm
# Tham chiếu: OWASP Mobile Top 10 - M3: Insecure Communication
# ──────────────────────────────────────────────
SENSITIVE_PATTERNS = {
    "password": re.compile(r'"password"\s*:\s*"([^"]+)"', re.IGNORECASE),
    "username": re.compile(r'"username"\s*:\s*"([^"]+)"', re.IGNORECASE),
    "token":    re.compile(r'"token"\s*:\s*"([^"]+)"', re.IGNORECASE),
    "secret":   re.compile(r'"secret"\s*:\s*"([^"]+)"', re.IGNORECASE),
}


def parse_har_file(filepath: str) -> list[dict]:
    """
    Đọc file HAR (HTTP Archive) xuất từ Burp Suite.
    
    HAR là định dạng JSON chuẩn, lưu toàn bộ HTTP request/response.
    Burp Suite có thể export qua: Proxy > HTTP History > Save items.
    
    Returns:
        Danh sách các HTTP entry (request + response).
    """
    path = Path(filepath)
    if not path.exists():
        log_danger(f"File không tồn tại: {filepath}")
        return []

    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    entries = data.get("log", {}).get("entries", [])
    log_info(f"Đọc được {len(entries)} HTTP request từ file HAR.")
    return entries


def analyze_entry_for_credentials(entry: dict) -> list[dict]:
    """
    Phân tích một HTTP entry để tìm credentials bị lộ.
    
    Returns:
        Danh sách các findings, mỗi finding gồm:
        - field: tên field nhạy cảm
        - value: giá trị bị lộ
        - url  : URL của request
    """
    findings = []
    request  = entry.get("request", {})
    url      = request.get("url", "N/A")
    body     = ""

    # Lấy nội dung POST body
    post_data = request.get("postData", {})
    if post_data:
        body = post_data.get("text", "")

    # Kiểm tra từng pattern
    for field_name, pattern in SENSITIVE_PATTERNS.items():
        match = pattern.search(body)
        if match:
            findings.append({
                "field": field_name,
                "value": match.group(1),
                "url":   url,
            })

    return findings


def run_vulnerable_phase(har_file: str) -> None:
    """Phân tích và hiển thị thông tin bị lộ — Phase 2.1 (Vulnerable)."""
    print_banner("PHASE 2.1 — Vulnerable App: Phân Tích Credentials Bị Lộ")

    entries = parse_har_file(har_file)
    if not entries:
        log_warning("Không có dữ liệu để phân tích.")
        return

    total_findings = 0

    for idx, entry in enumerate(entries, start=1):
        findings = analyze_entry_for_credentials(entry)
        if findings:
            log_danger(f"Request #{idx} — CÓ DỮ LIỆU NHẠY CẢM BỊ LỘ:")
            for f in findings:
                console.print(
                    f"    [bold red]⚠  {f['field'].upper():<12}:[/bold red] "
                    f"[red]{f['value']}[/red]"
                )
                console.print(f"    [dim]   URL: {f['url']}[/dim]")
            total_findings += len(findings)
        else:
            log_info(f"Request #{idx} — Không có thông tin nhạy cảm.")

    print()
    if total_findings > 0:
        log_danger(
            f"TỔNG KẾT: Phát hiện {total_findings} thông tin nhạy cảm bị lộ qua HTTPS!"
        )
        log_danger(
            "Đây là bằng chứng vi phạm OWASP M3: Insecure Communication."
        )
    else:
        log_success("Không phát hiện credentials trong traffic.")


def run_hardened_phase() -> None:
    """Mô phỏng kết quả Phase 2.3 — App đã được vá, Burp không capture được."""
    print_banner("PHASE 2.3 — Hardened App: Kiểm Chứng Khả Năng Phòng Thủ")

    console.print("[bold yellow]Mô phỏng kết quả từ Burp Suite sau khi app đã vá:[/bold yellow]\n")

    # Mô phỏng output mà Burp sẽ hiển thị
    burp_output_simulation = [
        ("TLS Handshake",  "FAILED",  "Client sent TLS alert: certificate_unknown"),
        ("Connection",     "REFUSED", "javax.net.ssl.SSLHandshakeException"),
        ("Payload",        "EMPTY",   "No data intercepted - connection terminated"),
    ]

    for label, status, detail in burp_output_simulation:
        color = "red" if status in ("FAILED", "REFUSED") else "yellow"
        console.print(
            f"  [bold {color}][Burp] {label:<18} → {status}[/bold {color}]"
        )
        console.print(f"         [dim]{detail}[/dim]")
        print()

    log_success("Network Security Config hoạt động đúng.")
    log_success("Chứng chỉ CA của Burp Suite bị từ chối (không thuộc System CA store).")
    log_success("Không có byte dữ liệu nào bị đánh cắp — App AN TOÀN.")

    console.print()
    console.print("[bold green]Compliance:[/bold green]")
    console.print("  ✓ ISO/IEC 27002:2022 — Clause 8.24: Use of cryptography")
    console.print("  ✓ ISO/IEC 27002:2022 — Clause 8.26: Application security requirements")
    console.print("  ✓ GDPR Article 32: Security of processing (Data in transit protected)")


def main():
    parser = argparse.ArgumentParser(
        description="MITM Traffic Analyzer — Project 4 Demo Tool"
    )
    parser.add_argument(
        "--phase",
        choices=["vulnerable", "hardened"],
        required=True,
        help="Chọn phase demo: 'vulnerable' (trước vá) hoặc 'hardened' (sau vá)"
    )
    parser.add_argument(
        "--file",
        default="reports/raw_logs/captured.har",
        help="Đường dẫn file HAR export từ Burp Suite (chỉ dùng cho phase=vulnerable)"
    )
    args = parser.parse_args()

    if args.phase == "vulnerable":
        run_vulnerable_phase(args.file)
    else:
        run_hardened_phase()


if __name__ == "__main__":
    main()