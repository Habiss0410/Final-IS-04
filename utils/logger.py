"""
logger.py - Centralized logging utility
Sử dụng thư viện `rich` để output đẹp trên terminal VSCode.
"""

from rich.console import Console
from rich.theme import Theme
import datetime

# Định nghĩa theme màu sắc cho từng cấp độ log
custom_theme = Theme({
    "info":    "bold cyan",
    "success": "bold green",
    "warning": "bold yellow",
    "danger":  "bold red",
    "header":  "bold white on dark_blue",
})

console = Console(theme=custom_theme)


def log_info(msg: str) -> None:
    """Log thông tin thông thường."""
    ts = datetime.datetime.now().strftime("%H:%M:%S")
    console.print(f"[info][ INFO  {ts} ][/info] {msg}")


def log_success(msg: str) -> None:
    """Log khi thao tác thành công."""
    ts = datetime.datetime.now().strftime("%H:%M:%S")
    console.print(f"[success][ OK    {ts} ][/success] {msg}")


def log_warning(msg: str) -> None:
    """Log cảnh báo."""
    ts = datetime.datetime.now().strftime("%H:%M:%S")
    console.print(f"[warning][ WARN  {ts} ][/warning] {msg}")


def log_danger(msg: str) -> None:
    """Log lỗi nghiêm trọng / phát hiện tấn công."""
    ts = datetime.datetime.now().strftime("%H:%M:%S")
    console.print(f"[danger][ CRIT  {ts} ][/danger] {msg}")


def print_banner(title: str) -> None:
    """In banner section cho mỗi phase."""
    console.print(f"\n[header]{'=' * 60}[/header]")
    console.print(f"[header]  {title.upper()}[/header]")
    console.print(f"[header]{'=' * 60}[/header]\n")