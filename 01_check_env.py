"""
01_check_env.py — Kiểm tra và xác nhận môi trường lab
Cách chạy: python python-tools/01_check_env.py
"""

import sys
import shutil
from utils.logger import print_banner, log_info, log_success, log_danger, log_warning
from utils.adb_helper import check_adb_installed, get_connected_devices


def check_python_version() -> bool:
    major, minor = sys.version_info.major, sys.version_info.minor
    if major < 3 or (major == 3 and minor < 10):
        log_danger(f"Python {major}.{minor} không đủ. Cần >= 3.10.")
        return False
    log_success(f"Python {major}.{minor} — OK")
    return True


def check_required_tools() -> bool:
    tools = {
        "adb":  "Android SDK Platform Tools",
        "java": "Java JDK (để build Android app)",
    }
    all_ok = True
    for tool, description in tools.items():
        if shutil.which(tool):
            log_success(f"  {tool:8s} → Tìm thấy   ({description})")
        else:
            log_warning(f"  {tool:8s} → Thiếu!     ({description})")
            all_ok = False
    return all_ok


def check_avd_connection() -> bool:
    if not check_adb_installed():
        return False
    devices = get_connected_devices()
    if not devices:
        log_danger("Không tìm thấy AVD nào. Hãy khởi động Android Emulator.")
        return False
    for d in devices:
        log_success(f"  Thiết bị: {d}")
    return True


def main():
    print_banner("PROJECT 4 — Environment Check")

    results = {
        "Python Version >= 3.10": check_python_version(),
        "Required CLI Tools":     check_required_tools(),
        "AVD Connected via ADB":  check_avd_connection(),
    }

    print()
    log_info("─── Kết quả tổng hợp ───")
    from utils.logger import console
    all_passed = True
    for check_name, passed in results.items():
        status = "[green]✓ PASS[/green]" if passed else "[red]✗ FAIL[/red]"
        console.print(f"  {status}  {check_name}")
        if not passed:
            all_passed = False

    print()
    if all_passed:
        log_success("Môi trường sẵn sàng! Chạy tiếp 02_capture_traffic.py")
    else:
        log_danger("Cần khắc phục các lỗi trên trước khi tiếp tục.")


if __name__ == "__main__":
    main()