"""
mallory.py – TV3
Kẻ tấn công đứng giữa (MITM): Alice tưởng đang nói chuyện với Bob nhưng thực ra
kết nối tới Mallory. Mallory thay khóa công khai của hai bên bằng khóa của mình,
nhờ đó có hai khóa chung (một với Alice, một với Bob), đọc và sửa được tin nhắn.

Chạy riêng: python mallory.py [--listen-port 5001] [--bob-port 5000]
"""

import argparse
import socket

from channel import HOST, BOB_PORT, MALLORY_PORT, send_msg, recv_msg, log_step
from dh_protocol import (
    generate_private_key,
    compute_public_key,
    compute_shared_secret,
    derive_aes_key,
    encrypt_message,
    decrypt_message,
)


def run_mallory(listen_port: int = MALLORY_PORT, bob_port: int = BOB_PORT) -> None:
    """Chặn trao đổi khóa DH giữa Alice và Bob, đọc và sửa tin nhắn.
    Nếu Bob từ chối chữ ký thì chuyển lỗi về Alice và kết thúc."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind((HOST, listen_port))
            server.listen(1)
            log_step("Mallory", f"Đang chờ Alice tại {HOST}:{listen_port}")

            alice_sock, _ = server.accept()
            with alice_sock, alice_sock.makefile("r", encoding="utf-8") as alice_reader:
                log_step("Mallory", "Alice đã kết nối.")
                init = recv_msg(alice_reader)
                if not isinstance(init, dict) or init.get("type") != "dh_init":
                    raise ValueError("Alice không gửi thông điệp dh_init hợp lệ")

                p, g, a_public = init["p"], init["g"], init["public"]
                if not all(type(x) is int for x in (p, g, a_public)):
                    raise ValueError("Các tham số p, g, public phải là số nguyên")
                if p < 5 or not (2 <= g < p) or not (2 <= a_public <= p - 2):
                    raise ValueError("Tham số Diffie-Hellman không hợp lệ")

                # Mỗi đầu kết nối có một cặp khóa DH riêng của Mallory.
                m1 = generate_private_key(p)
                m1_public = compute_public_key(g, m1, p)
                k_alice = derive_aes_key(compute_shared_secret(a_public, m1, p))

                m2 = generate_private_key(p)
                m2_public = compute_public_key(g, m2, p)

                with socket.create_connection((HOST, bob_port)) as bob_sock:
                    with bob_sock.makefile("r", encoding="utf-8") as bob_reader:
                        log_step("Mallory", f"Đã kết nối tới Bob tại {HOST}:{bob_port}")

                        # Giữ nguyên chữ ký của Alice nếu có; Mallory không thể ký lại.
                        # Vì trường public đã bị đổi, Bob sẽ phát hiện ở chế độ auth.
                        fake_init = dict(init)
                        fake_init["public"] = m2_public
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
                        if type(b_public) is not int or not (2 <= b_public <= p - 2):
                            raise ValueError("Khóa công khai của Bob không hợp lệ")
                        k_bob = derive_aes_key(compute_shared_secret(b_public, m2, p))

                        # Mallory đưa M1 cho Alice thay cho khóa B của Bob.
                        fake_reply = dict(reply)
                        fake_reply["public"] = m1_public
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
    args = parser.parse_args()
    run_mallory(listen_port=args.listen_port, bob_port=args.bob_port)
