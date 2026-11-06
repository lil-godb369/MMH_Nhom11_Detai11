"""
bob.py – TV2
Bên Bob (server): chờ một kết nối, trả lời trao đổi khóa Diffie-Hellman,
giải mã tin nhắn nhận được và gửi tin trả lời đã mã hóa.

Chạy riêng:  python bob.py [--port 5000] [--auth]
"""

import argparse
import socket  # noqa: F401  (dùng khi cài đặt)

from channel import HOST, BOB_PORT, send_msg, recv_msg  # noqa: F401
from dh_protocol import (  # noqa: F401
    generate_private_key,
    compute_public_key,
    compute_shared_secret,
    is_valid_public_key,
    derive_aes_key,
    encrypt_message,
    decrypt_message,
)
from dh_auth import load_private_key, load_public_key, sign_dh_public, verify_dh_public  # noqa: F401


def run_bob(port: int = BOB_PORT, auth: bool = False) -> None:
    """Chờ một kết nối, gửi dh_reply, giải mã tin nhắn, gửi tin trả lời."""
    # TODO(TV2):
    #   1. srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    #      srv.bind((HOST, port)); srv.listen(1); in "Bob đang chờ ở cổng ..."
    #   2. conn, addr = srv.accept(); reader = conn.makefile("r", encoding="utf-8")
    #   3. Nhận dh_init -> p, g, A. Kiểm tra is_valid_public_key(A, p).
    #      Nếu auth: verify_dh_public(load_public_key("alice"), p, g, A, bytes.fromhex(msg["signature"]))
    #      Sai -> in "Phát hiện MITM", gửi {"type": "error", "reason": "..."} rồi đóng kết nối.
    #   4. b = generate_private_key(p); B = compute_public_key(g, b, p)
    #      Gửi {"type": "dh_reply", "public": B} (+ "signature" nếu auth, ký bằng khóa "bob")
    #   5. Nhận tin "data" -> giải mã -> in ra; gửi tin trả lời đã mã hóa.
    #   6. Đóng conn và srv.
    raise NotImplementedError("TV2: run_bob chưa cài đặt")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Bên Bob (server)")
    parser.add_argument("--port", type=int, default=BOB_PORT, help="cổng Bob lắng nghe")
    parser.add_argument("--auth", action="store_true", help="bật xác thực bằng chữ ký RSA")
    args = parser.parse_args()
    run_bob(port=args.port, auth=args.auth)
