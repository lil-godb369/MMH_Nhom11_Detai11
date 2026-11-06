"""
channel.py – TV2
Kênh truyền công khai giữa các bên qua socket TCP.
Mỗi tin nhắn là MỘT dòng JSON, kết thúc bằng ký tự xuống dòng "\\n".
send_msg in ra những gì kẻ nghe lén nhìn thấy trên đường truyền.
"""

import json  # noqa: F401  (dùng khi cài đặt)

HOST = "127.0.0.1"
BOB_PORT = 5000
MALLORY_PORT = 5001


def send_msg(sock, msg: dict) -> None:
    """Gửi dict `msg` dưới dạng một dòng JSON; in ra những gì kẻ nghe lén thấy."""
    # TODO(TV2):
    #   1. line = json.dumps(msg) + "\n"
    #   2. sock.sendall(line.encode("utf-8"))
    #   3. In ra màn hình, ví dụ: [Kênh công khai] {"type": "dh_init", ...}
    #      (số lớn có thể rút gọn cho dễ đọc, vd 12345...6789)
    raise NotImplementedError("TV2: send_msg chưa cài đặt")


def recv_msg(reader) -> dict:
    """Đọc một dòng JSON từ `reader` và trả về dict.

    reader = sock.makefile("r", encoding="utf-8"), mỗi kết nối chỉ tạo một lần.
    """
    # TODO(TV2):
    #   1. line = reader.readline()
    #   2. Nếu line rỗng: bên kia đã đóng kết nối -> raise ConnectionError(...)
    #   3. return json.loads(line)
    raise NotImplementedError("TV2: recv_msg chưa cài đặt")


if __name__ == "__main__":
    # TODO(TV2): tự thử bằng socket.socketpair(): gửi một dict rồi đọc lại.
    print("channel.py: chưa có phần tự kiểm thử")
