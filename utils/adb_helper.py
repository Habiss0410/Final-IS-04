"""
adb_helper.py - Wrapper cho các lệnh ADB (Android Debug Bridge)

Mục đích học thuật:
  Thay vì gõ tay từng lệnh adb trong Terminal, module này
  wrap chúng lại thành các hàm Python có thể kiểm soát,
  log, và tái sử dụng trong các script tự động.
"""

import subprocess
import shutil
from utils.logger import log_info, log_success, log_danger, log_warning


def _run(cmd: list[str], timeout: int = 15) -> tuple[str, str, int]:
    """
    Hàm nội bộ: chạy một lệnh shell và trả về (stdout, stderr, returncode).
    Không raise exception - caller tự xử lý.
    """
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout
    )
    return result.stdout.strip(), result.stderr.strip(), result.returncode


def check_adb_installed() -> bool:
    """Kiểm tra xem ADB có trong PATH của hệ thống không."""
    if shutil.which("adb") is None:
        log_danger("ADB không tìm thấy trong PATH. Hãy cài Android SDK.")
        return False
    log_success("ADB đã được cài đặt.")
    return True


def get_connected_devices() -> list[str]:
    """
    Trả về danh sách serial của các thiết bị/AVD đang kết nối.
    Ví dụ: ['emulator-5554']
    """
    stdout, _, _ = _run(["adb", "devices"])
    lines = stdout.splitlines()
    devices = []
    for line in lines[1:]:   # Bỏ dòng tiêu đề "List of devices attached"
        if "\tdevice" in line:
            serial = line.split("\t")[0]
            devices.append(serial)
    return devices


def get_app_data_path(package_name: str) -> str:
    """Trả về đường dẫn data directory của app trên thiết bị."""
    return f"/data/data/{package_name}"


def read_shared_prefs(package_name: str, pref_filename: str) -> str | None:
    """
    Đọc nội dung file SharedPreferences của một app.
    
    Yêu cầu: AVD phải chạy với quyền root (thường AVD mặc định có).
    
    Args:
        package_name : VD "com.demo.mitm"
        pref_filename: VD "login_data.xml"
    
    Returns:
        Nội dung file dưới dạng string, hoặc None nếu thất bại.
    """
    path = f"/data/data/{package_name}/shared_prefs/{pref_filename}"
    log_info(f"Đang đọc: {path}")
    stdout, stderr, code = _run(["adb", "shell", "su", "0", "cat", path])

    if code != 0:
        log_warning(f"Không thể đọc file. Lỗi: {stderr}")
        return None

    return stdout


def capture_logcat(filter_tag: str = "DEBUG", duration_sec: int = 10) -> list[str]:
    """
    Chạy adb logcat trong `duration_sec` giây và lọc theo tag.
    
    Trong môi trường demo, hàm này mô phỏng việc hacker
    nghe lén luồng log để bắt dữ liệu nhạy cảm.
    
    Returns:
        Danh sách các dòng log phù hợp.
    """
    log_info(f"Bắt đầu capture logcat (tag={filter_tag}, {duration_sec}s)...")
    try:
        stdout, _, _ = _run(
            ["adb", "logcat", "-d", f"{filter_tag}:D", "*:S"],
            timeout=duration_sec + 5
        )
        lines = [l for l in stdout.splitlines() if filter_tag in l]
        return lines
    except subprocess.TimeoutExpired:
        log_warning("Logcat timeout - trả về kết quả hiện tại.")
        return []


def launch_activity(package_name: str, activity_name: str) -> bool:
    """
    Khởi động trực tiếp một Activity bằng adb.
    
    Đây là kỹ thuật 'Activity Bypass' - khai thác lỗ hổng
    android:exported="true" để nhảy qua màn hình Login.
    
    Args:
        package_name : VD "com.demo.mitm"
        activity_name: VD ".DashboardActivity"
    
    Returns:
        True nếu launch thành công, False nếu bị chặn.
    """
    component = f"{package_name}/{activity_name}"
    log_info(f"Thử launch: {component}")
    stdout, stderr, code = _run(
        ["adb", "shell", "am", "start", "-n", component]
    )

    if "SecurityException" in stderr or "Permission Denial" in stderr:
        log_success("Activity bị chặn đúng cách! (SecurityException)")
        return False

    if "Error" in stdout or code != 0:
        log_danger(f"Lỗi không xác định: {stderr}")
        return False

    log_danger("BYPASS THÀNH CÔNG - Activity mở được mà không cần đăng nhập!")
    return True