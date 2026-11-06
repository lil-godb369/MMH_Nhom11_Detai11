"""
mallory.py – TV3
Kẻ tấn công đứng giữa (MITM): Alice tưởng đang nói chuyện với Bob nhưng thực ra
kết nối tới Mallory. Mallory thay khóa công khai của hai bên bằng khóa của mình,
nhờ đó có hai khóa chung (một với Alice, một với Bob), đọc và sửa được tin nhắn.

Chạy riêng:  python mallory.py [--listen-port 5001] [--bob-port 5000]
"""

import argparse
import socket  # noqa: F401  (dùng khi cài đặt)

from channel import HOST, BOB_PORT, MALLORY_PORT, send_msg, recv_msg  # noqa: F401
from dh_protocol import (  # noqa: F401
    generate_private_key,
    compute_public_key,
    compute_shared_secret,
    derive_aes_key,
    encrypt_message,
    decrypt_message,
)


def run_mallory(listen_port: int = MALLORY_PORT, bob_port: int = BOB_PORT) -> None:
    """Nhận kết nối của Alice, tự kết nối tới Bob, thay khóa công khai của hai bên
    bằng khóa của Mallory, đọc và sửa tin nhắn rồi chuyển tiếp."""
    # TODO(TV3):
    #   1. Mở cổng listen_port (nhớ SO_REUSEADDR), chờ Alice kết nối.
    #   2. Nhận dh_init của Alice -> p, g, A.
    #      Sinh m1, M1 = g^m1 mod p; khóa với Alice: k_alice = derive_aes_key(A^m1 mod p)
    #   3. Kết nối tới (HOST, bob_port). Sinh m2, M2.
    #      Gửi Bob dh_init với "public": M2 (giữ nguyên "signature" của Alice nếu có).
    #   4. Nhận trả lời của Bob.
    #      Nếu type == "error" (chế độ auth): in ra, chuyển tiếp cho Alice rồi dừng.
    #      Nếu dh_reply: B -> k_bob = derive_aes_key(B^m2 mod p).
    #      Gửi Alice dh_reply với "public": M1.
    #   5. Nhận "data" của Alice: giải mã bằng k_alice, in nội dung đọc trộm được,
    #      sửa nội dung (vd "100.000" -> "900.000"), mã hóa lại bằng k_bob, gửi Bob.
    #   6. Nhận trả lời của Bob: giải mã bằng k_bob, mã hóa lại bằng k_alice, gửi Alice.
    #   7. Đóng các kết nối.
    raise NotImplementedError("TV3: run_mallory chưa cài đặt")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Kẻ tấn công đứng giữa (Mallory)")
    parser.add_argument("--listen-port", type=int, default=MALLORY_PORT,
                        help="cổng Mallory chờ Alice kết nối")
    parser.add_argument("--bob-port", type=int, default=BOB_PORT, help="cổng của Bob")
    args = parser.parse_args()
    run_mallory(listen_port=args.listen_port, bob_port=args.bob_port)
