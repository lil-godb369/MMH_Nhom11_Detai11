"""Alice (client): trao đổi khóa DH và truyền dữ liệu mã hóa tới Bob."""
import argparse
import socket

from channel import HOST, BOB_PORT, send_msg, recv_msg, log_step
from dh_math import get_params
from dh_protocol import (
    generate_private_key, compute_public_key, compute_shared_secret,
    is_valid_public_key, derive_aes_key, encrypt_message, decrypt_message,
)
from dh_auth import load_private_key, load_public_key, sign_dh_public, verify_dh_public

DEFAULT_MESSAGE = "Chuyển 100.000đ vào tài khoản của Bob"


def run_alice(port: int = BOB_PORT, auth: bool = False, bits: int = 512,
              message: str = DEFAULT_MESSAGE) -> None:
    """Kết nối Bob, thực hiện DH, gửi và nhận thông điệp AES-GCM."""
    p, g = get_params(bits)
    private_a = generate_private_key(p)
    public_a = compute_public_key(g, private_a, p)
    init = {"type": "dh_init", "p": p, "g": g, "public": public_a}
    if auth:
        init["signature"] = sign_dh_public(
            load_private_key("alice"), p, g, public_a
        ).hex()

    log_step("Alice", "01 | KẾT NỐI", f"Đang kết nối tới {HOST}:{port}")
    with socket.create_connection((HOST, port), timeout=10) as sock:
        sock.settimeout(15)
        with sock.makefile("r", encoding="utf-8") as reader:
            log_step("Alice", "02 | GỬI KHÓA CÔNG KHAI DH")
            send_msg(sock, init)
            reply = recv_msg(reader)
            if reply.get("type") == "error":
                print(f"[Alice] {reply.get('reason', 'Bob từ chối kết nối')}")
                return
            if reply.get("type") != "dh_reply":
                raise ValueError("Alice chờ dh_reply nhưng nhận loại tin khác")
            public_b = reply.get("public")
            if not is_valid_public_key(public_b, p):
                raise ValueError("Khóa công khai của Bob không hợp lệ")
            if auth:
                try:
                    signature = bytes.fromhex(reply["signature"])
                except (KeyError, TypeError, ValueError) as exc:
                    raise ValueError("Phát hiện MITM: chữ ký Bob bị thiếu hoặc sai định dạng") from exc
                if not verify_dh_public(
                    load_public_key("bob"), p, g, public_b, signature
                ):
                    raise ValueError("Phát hiện MITM: chữ ký khóa DH của Bob không hợp lệ")

            log_step("Alice", "03 | NHẬN KHÓA CÔNG KHAI CỦA BOB")
            shared = compute_shared_secret(public_b, private_a, p)
            key = derive_aes_key(shared)
            log_step("Alice", "04 | TẠO KHÓA PHIÊN AES-256", "Đã tính khóa chung Diffie–Hellman")
            nonce, ciphertext = encrypt_message(key, message)
            log_step("Alice", "05 | GỬI TIN NHẮN ĐÃ MÃ HÓA", f"Bản rõ: {message}")
            send_msg(sock, {
                "type": "data", "nonce": nonce.hex(), "ciphertext": ciphertext.hex()
            })
            reply = recv_msg(reader)
            if reply.get("type") == "error":
                raise ValueError(reply.get("reason", "Bob báo lỗi"))
            if reply.get("type") != "data":
                raise ValueError("Alice chờ data nhưng nhận loại tin khác")
            try:
                plain = decrypt_message(
                    key, bytes.fromhex(reply["nonce"]),
                    bytes.fromhex(reply["ciphertext"]),
                )
            except (KeyError, TypeError, ValueError) as exc:
                raise ValueError(f"Alice không giải mã được phản hồi: {exc}") from exc
            log_step("Alice", "06 | GIẢI MÃ PHẢN HỒI THÀNH CÔNG", f"Bob trả lời: {plain}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Bên Alice (client)")
    parser.add_argument("--port", type=int, default=BOB_PORT)
    parser.add_argument("--auth", action="store_true")
    parser.add_argument("--bits", type=int, default=512)
    parser.add_argument("--message", default=DEFAULT_MESSAGE)
    args = parser.parse_args()
    try:
        run_alice(port=args.port, auth=args.auth, bits=args.bits, message=args.message)
    except (ValueError, ConnectionError, OSError) as exc:
        print(f"[Alice] Lỗi: {exc}")
        raise SystemExit(1) from None
