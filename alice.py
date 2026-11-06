"""
alice.py – TV2
Bên Alice (client): khởi tạo trao đổi khóa Diffie-Hellman với Bob,
gửi một tin nhắn đã mã hóa và nhận tin trả lời.

Chạy riêng:  python alice.py [--port 5001] [--auth] [--bits 512] [--message "..."]
"""

import argparse
import socket  # noqa: F401  (dùng khi cài đặt)

from channel import HOST, BOB_PORT, send_msg, recv_msg  # noqa: F401
from dh_math import get_params  # noqa: F401
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

DEFAULT_MESSAGE = "Chuyển 100.000đ vào tài khoản của Bob"


def run_alice(port: int = BOB_PORT, auth: bool = False, bits: int = 512,
              message: str = DEFAULT_MESSAGE) -> None:
    """Kết nối, gửi dh_init, nhận dh_reply, gửi tin nhắn đã mã hóa, nhận tin trả lời."""
    # TODO(TV2):
    #   1. p, g = get_params(bits); a = generate_private_key(p); A = compute_public_key(g, a, p)
    #   2. Kết nối tới (HOST, port); reader = sock.makefile("r", encoding="utf-8")
    #   3. Gửi {"type": "dh_init", "p": p, "g": g, "public": A}
    #      Nếu auth: thêm "signature": sign_dh_public(load_private_key("alice"), p, g, A).hex()
    #   4. Nhận tin trả lời. Nếu type == "error": in lý do rồi dừng.
    #      Kiểm tra is_valid_public_key(B, p).
    #      Nếu auth: verify_dh_public(load_public_key("bob"), p, g, B, bytes.fromhex(...)),
    #      sai thì in "Phát hiện MITM" và dừng.
    #   5. key = derive_aes_key(compute_shared_secret(B, a, p))
    #   6. nonce, ct = encrypt_message(key, message)
    #      Gửi {"type": "data", "nonce": nonce.hex(), "ciphertext": ct.hex()}
    #   7. Nhận tin trả lời của Bob, giải mã, in ra, đóng kết nối.
    raise NotImplementedError("TV2: run_alice chưa cài đặt")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Bên Alice (client)")
    parser.add_argument("--port", type=int, default=BOB_PORT,
                        help="5000 = nói thẳng với Bob, 5001 = đi qua Mallory")
    parser.add_argument("--auth", action="store_true", help="bật xác thực bằng chữ ký RSA")
    parser.add_argument("--bits", type=int, default=512, help="độ dài p (bit)")
    parser.add_argument("--message", default=DEFAULT_MESSAGE, help="tin nhắn gửi cho Bob")
    args = parser.parse_args()
    run_alice(port=args.port, auth=args.auth, bits=args.bits, message=args.message)
