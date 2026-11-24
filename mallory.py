"""
mallory.py – TV3
Kẻ tấn công đứng giữa (MITM): Alice tưởng đang nói chuyện với Bob nhưng thực ra
kết nối tới Mallory. Mallory thay khóa công khai của hai bên bằng khóa của mình,
nhờ đó có hai khóa chung (một với Alice, một với Bob), đọc và sửa được tin nhắn.

Chế độ (--mode):
  both      thay khóa công khai ở cả hai chiều (mặc định) -> có xác thực thì Bob phát hiện trước
  bob-only  chuyển nguyên dh_init của Alice, chỉ thay khóa trong dh_reply của Bob
            -> dùng để demo Alice tự phát hiện MITM khi có xác thực
--forge: Mallory tự ký khóa giả bằng khóa RSA "mallory" thay vì giữ chữ ký cũ.

Chạy riêng: python mallory.py [--listen-port 5001] [--bob-port 5000] [--mode both|bob-only] [--forge]
"""

import argparse
import socket

from channel import HOST, BOB_PORT, MALLORY_PORT, send_msg, recv_msg, log_step
from dh_protocol import (
    generate_private_key,
    compute_public_key,
    compute_shared_secret,
    is_valid_public_key,
    is_valid_params,
    derive_aes_key,
    encrypt_message,
    decrypt_message,
)
from dh_auth import generate_signing_keys, load_private_key, sign_dh_public

MODES = ("both", "bob-only")


def _load_mallory_key():
    """Đọc khóa riêng RSA của Mallory, chưa có thì sinh mới (dùng cho --forge)."""
    try:
        return load_private_key("mallory")
    except FileNotFoundError:
        generate_signing_keys("mallory")
        return load_private_key("mallory")


def run_mallory(listen_port: int = MALLORY_PORT, bob_port: int = BOB_PORT,
                mode: str = "both", forge: bool = False) -> None:
    """Chặn trao đổi khóa DH giữa Alice và Bob, đọc và sửa tin nhắn.
    Bên nào báo lỗi (phát hiện MITM) thì chuyển lỗi sang bên kia và kết thúc."""
    if mode not in MODES:
        raise ValueError(f"mode phải là một trong {MODES}")
    mallory_rsa = _load_mallory_key() if forge else None
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind((HOST, listen_port))
            server.listen(1)
            log_step("Mallory", f"Đang chờ Alice tại {HOST}:{listen_port}",
                     f"Chế độ: {mode}" + (" | tự ký khóa giả bằng RSA của Mallory" if forge else ""))

            alice_sock, _ = server.accept()
            with alice_sock, alice_sock.makefile("r", encoding="utf-8") as alice_reader:
                log_step("Mallory", "Alice đã kết nối.")
                init = recv_msg(alice_reader)
                if not isinstance(init, dict) or init.get("type") != "dh_init":
                    raise ValueError("Alice không gửi thông điệp dh_init hợp lệ")

                p, g, a_public = init["p"], init["g"], init["public"]
                # Dùng chung tiêu chí với Bob để không chuyển tiếp tham số Bob sẽ từ chối.
                if not is_valid_params(p, g):
                    raise ValueError("Tham số Diffie-Hellman không hợp lệ")
                if not is_valid_public_key(a_public, p):
                    raise ValueError("Khóa công khai của Alice không hợp lệ")

                # Mỗi đầu kết nối có một cặp khóa DH riêng của Mallory.
                m1 = generate_private_key(p)
                m1_public = compute_public_key(g, m1, p)
                k_alice = derive_aes_key(compute_shared_secret(a_public, m1, p), p)

                m2 = generate_private_key(p)
                m2_public = compute_public_key(g, m2, p)

                with socket.create_connection((HOST, bob_port)) as bob_sock:
                    with bob_sock.makefile("r", encoding="utf-8") as bob_reader:
                        log_step("Mallory", f"Đã kết nối tới Bob tại {HOST}:{bob_port}")

                        if mode == "bob-only":
                            # Chuyển nguyên dh_init: Bob nhận đúng khóa A và chữ ký của Alice.
                            send_msg(bob_sock, init)
                            log_step("Mallory", "Chuyển nguyên dh_init của Alice cho Bob (bob-only).")
                        else:
                            # Không --forge: giữ nguyên chữ ký của Alice (không khớp khóa mới).
                            # --forge: tự ký bằng khóa RSA của Mallory. Cả hai cách Bob đều phát hiện.
                            fake_init = dict(init)
                            fake_init["public"] = m2_public
                            if forge:
                                fake_init["signature"] = sign_dh_public(mallory_rsa, p, g, m2_public).hex()
                            send_msg(bob_sock, fake_init)
                            log_step("Mallory", "Đã thay khóa công khai Alice gửi cho Bob.")

                        reply = recv_msg(bob_reader)
                        if not isinstance(reply, dict):
                            raise ValueError("Phản hồi của Bob không hợp lệ")
                        if reply.get("type") == "error":
                            log_step("Mallory", f"Bob từ chối: {reply.get('reason', 'Không rõ lý do')}")
                            send_msg(alice_sock, reply)
                            return
                        if reply.get("type") != "dh_reply":
                            raise ValueError("Bob không gửi dh_reply")

                        b_public = reply["public"]
                        if not is_valid_public_key(b_public, p):
                            raise ValueError("Khóa công khai của Bob không hợp lệ")
                        # bob-only: Bob dùng khóa A thật nên Mallory không tính được khóa chung với Bob.
                        k_bob = (None if mode == "bob-only"
                                 else derive_aes_key(compute_shared_secret(b_public, m2, p), p))

                        # Mallory đưa M1 cho Alice thay cho khóa B của Bob.
                        fake_reply = dict(reply)
                        fake_reply["public"] = m1_public
                        if forge:
                            fake_reply["signature"] = sign_dh_public(mallory_rsa, p, g, m1_public).hex()
                        send_msg(alice_sock, fake_reply)
                        log_step("Mallory", "Đã thay khóa công khai Bob gửi cho Alice.")

                        # Alice gửi dữ liệu được bảo vệ bằng khóa chung với Mallory.
                        from_alice = recv_msg(alice_reader)
                        if not isinstance(from_alice, dict):
                            raise ValueError("Phản hồi của Alice không hợp lệ")
                        if from_alice.get("type") == "error":
                            log_step("Mallory", f"Alice từ chối: {from_alice.get('reason', 'Không rõ lý do')}")
                            send_msg(bob_sock, from_alice)
                            return
                        if from_alice.get("type") != "data":
                            raise ValueError("Alice không gửi dữ liệu")

                        original = decrypt_message(
                            k_alice,
                            bytes.fromhex(from_alice["nonce"]),
                            bytes.fromhex(from_alice["ciphertext"]),
                        )
                        log_step("Mallory", f"Đọc được tin Alice: {original}")

                        # Nếu không có số tiền mẫu, vẫn sửa nội dung để thấy tác động MITM.
                        if "100.000" in original:
                            modified = original.replace("100.000", "900.000")
                        else:
                            modified = original + " [Mallory đã sửa nội dung]"
                        log_step("Mallory", f"Nội dung sau khi sửa: {modified}")

                        if k_bob is None:
                            # bob-only, không xác thực: không có khóa chung với Bob để mã hóa lại,
                            # đành chuyển nguyên bản mã -> Bob giải mã thất bại và báo lỗi.
                            log_step("Mallory", "Không có khóa chung với Bob, chuyển nguyên bản mã.")
                            send_msg(bob_sock, from_alice)
                        else:
                            nonce, ciphertext = encrypt_message(k_bob, modified)
                            send_msg(bob_sock, {
                                "type": "data",
                                "nonce": nonce.hex(),
                                "ciphertext": ciphertext.hex(),
                            })

                        # Bob trả lời bằng k_bob; Mallory mã hóa lại bằng k_alice.
                        from_bob = recv_msg(bob_reader)
                        if not isinstance(from_bob, dict):
                            raise ValueError("Phản hồi dữ liệu của Bob không hợp lệ")
                        if from_bob.get("type") == "error":
                            log_step("Mallory", f"Bob báo lỗi: {from_bob.get('reason', 'Không rõ lý do')}")
                            send_msg(alice_sock, from_bob)
                            return
                        if from_bob.get("type") != "data":
                            raise ValueError("Bob không gửi dữ liệu trả lời")

                        bob_text = decrypt_message(
                            k_bob,
                            bytes.fromhex(from_bob["nonce"]),
                            bytes.fromhex(from_bob["ciphertext"]),
                        )
                        log_step("Mallory", f"Đọc được tin Bob: {bob_text}")
                        nonce, ciphertext = encrypt_message(k_alice, bob_text)
                        send_msg(alice_sock, {
                            "type": "data",
                            "nonce": nonce.hex(),
                            "ciphertext": ciphertext.hex(),
                        })
                        log_step("Mallory", "Đã chuyển tiếp phản hồi cho Alice.")
    except (OSError, ValueError, KeyError, TypeError, EOFError) as exc:
        log_step("Mallory", f"Lỗi: {exc}")
    finally:
        log_step("Mallory", "Kết thúc phiên kết nối.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Kẻ tấn công đứng giữa (Mallory)")
    parser.add_argument("--listen-port", type=int, default=MALLORY_PORT,
                        help="cổng Mallory chờ Alice kết nối")
    parser.add_argument("--bob-port", type=int, default=BOB_PORT,
                        help="cổng của Bob")
    parser.add_argument("--mode", choices=MODES, default="both",
                        help="both: thay khóa cả hai chiều; bob-only: chỉ thay khóa trong dh_reply của Bob")
    parser.add_argument("--forge", action="store_true",
                        help="tự ký khóa giả bằng khóa RSA của Mallory thay vì giữ chữ ký cũ")
    args = parser.parse_args()
    run_mallory(listen_port=args.listen_port, bob_port=args.bob_port,
                mode=args.mode, forge=args.forge)
