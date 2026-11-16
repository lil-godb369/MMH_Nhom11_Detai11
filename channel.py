"""Kênh truyền công khai Alice–Bob qua TCP, mỗi tin nhắn một dòng JSON."""

import json
import socket
import sys
import threading
from contextlib import closing

# Windows: khi chuyển output ra file/pipe (vd lưu log làm báo cáo) Python mặc định dùng cp1252
# và báo UnicodeEncodeError với tiếng Việt -> ép stdout/stderr sang UTF-8.
for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(encoding="utf-8")

HOST = "127.0.0.1"
BOB_PORT = 5000
MALLORY_PORT = 5001

# Giữ từng khối log liền nhau khi Alice/Bob chạy trên hai luồng.
_PRINT_LOCK = threading.Lock()


def log_step(actor: str, title: str, detail: str = "") -> None:
    """In một bước của giao thức, không ảnh hưởng dữ liệu truyền qua socket."""
    with _PRINT_LOCK:
        print(f"\n  [{actor.upper():7}] {title}", flush=True)
        if detail:
            print(f"            {detail}", flush=True)


def _short(value, limit=28) -> str:
    """Hiển thị gọn dữ liệu dài. Chỉ dùng cho log, không sửa dữ liệu thực."""
    raw = str(value)
    if len(raw) > limit + 9:
        return raw[:limit] + "..." + raw[-8:]
    return raw


def _display_wire(msg: dict) -> None:
    """Log sự kiện truyền dữ liệu dưới dạng dễ đọc."""
    kind = msg.get("type", "unknown")
    lines = []
    if kind == "dh_init":
        lines = [f"p: {msg['p'].bit_length()} bit  |  g: {msg['g']}",
                 f"Public DH: {_short(msg.get('public'))}"]
    elif kind == "dh_reply":
        lines = [f"Public DH: {_short(msg.get('public'))}"]
    elif kind == "data":
        lines = [f"Nonce: {_short(msg.get('nonce'))}",
                 f"Ciphertext: {_short(msg.get('ciphertext'))}"]
    elif kind == "error":
        lines = [f"Lý do: {msg.get('reason', 'không rõ')}"]
    else:
        lines = [f"Nội dung: {_short(msg, 55)}"]
    if "signature" in msg:
        lines.append(f"Chữ ký RSA: {_short(msg['signature'])}")
    with _PRINT_LOCK:
        print(f"  {'-' * 54}", flush=True)
        print(f"  [CHANNEL] Gói tin {str(kind).upper()}", flush=True)
        for line in lines:
            print(f"            {line}", flush=True)


def send_msg(sock, msg: dict) -> None:
    """Gửi một dict dạng JSON + newline và hiển thị dữ liệu trên kênh."""
    if not isinstance(msg, dict):
        raise ValueError("Tin nhắn phải là một đối tượng JSON (dict)")
    line = json.dumps(msg, ensure_ascii=False) + "\n"
    _display_wire(msg)  # in trước khi gửi để log luôn đúng thứ tự gửi -> nhận
    sock.sendall(line.encode("utf-8"))


def recv_msg(reader) -> dict:
    """Nhận một dòng JSON từ socket reader, báo lỗi nếu không hợp lệ."""
    line = reader.readline()
    if not line:
        raise ConnectionError("Bên kia đã đóng kết nối")
    try:
        msg = json.loads(line)
    except json.JSONDecodeError as exc:
        raise ValueError("Dữ liệu nhận được không phải JSON hợp lệ") from exc
    if not isinstance(msg, dict):
        raise ValueError("Dữ liệu nhận được phải là đối tượng JSON (dict)")
    return msg


if __name__ == "__main__":
    sender, receiver = socket.socketpair()
    with closing(sender), closing(receiver):
        with receiver.makefile("r", encoding="utf-8") as reader:
            sample = {"type": "test", "message": "Xin chào Alice và Bob!"}
            send_msg(sender, sample)
            result = recv_msg(reader)
            assert result == sample
            log_step("TEST", "Gửi/nhận JSON thành công", f"Tin nhắn: {result['message']}")
