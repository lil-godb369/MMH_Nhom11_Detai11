"""Bob (server): phản hồi DH, nhận và trả lời tin nhắn mã hóa."""
import argparse
import socket

from channel import HOST, BOB_PORT, send_msg, recv_msg, log_step
from dh_protocol import (
    generate_private_key, compute_public_key, compute_shared_secret,
    is_valid_public_key, derive_aes_key, encrypt_message, decrypt_message,
)
from dh_auth import load_private_key, load_public_key, sign_dh_public, verify_dh_public


def run_bob(port: int = BOB_PORT, auth: bool = False) -> None:
    """Nhận một kết nối Alice, trao đổi DH và phản hồi bằng AES-GCM."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((HOST, port))
        server.listen(1)
        log_step("Bob", "01 | CHO KẾT NỐI", f"Đang lắng nghe tại {HOST}:{port}")
        with server.accept()[0] as conn:
            conn.settimeout(15)
            with conn.makefile("r", encoding="utf-8") as reader:
                try:
                    init = recv_msg(reader)
                    log_step("Bob", "02 | NHẬN KHÓA CÔNG KHAI CỦA ALICE")
                    if init.get("type") != "dh_init":
                        raise ValueError("Bob chờ dh_init nhưng nhận loại tin khác")
                    p, g, public_a = init["p"], init["g"], init["public"]
                    if (not isinstance(p, int) or isinstance(p, bool)
                            or not isinstance(g, int) or isinstance(g, bool)
                            or p < 5 or not 2 <= g <= p - 2):
                        raise ValueError("Tham số DH p hoặc g không hợp lệ")
                    if not is_valid_public_key(public_a, p):
                        raise ValueError("Khóa công khai của Alice không hợp lệ")
                    if auth:
                        try:
                            signature = bytes.fromhex(init["signature"])
                        except (KeyError, TypeError, ValueError) as exc:
                            raise ValueError("Phát hiện MITM: thiếu hoặc sai chữ ký Alice") from exc
                        if not verify_dh_public(
                            load_public_key("alice"), p, g, public_a, signature
                        ):
                            raise ValueError("Phát hiện MITM: chữ ký khóa DH của Alice không hợp lệ")

                    private_b = generate_private_key(p)
                    public_b = compute_public_key(g, private_b, p)
                    reply = {"type": "dh_reply", "public": public_b}
                    if auth:
                        reply["signature"] = sign_dh_public(
                            load_private_key("bob"), p, g, public_b
                        ).hex()
                    log_step("Bob", "03 | GỬI KHÓA CÔNG KHAI DH")
                    send_msg(conn, reply)
                    key = derive_aes_key(compute_shared_secret(public_a, private_b, p))
                    log_step("Bob", "04 | TẠO KHÓA PHIÊN AES-256", "Đã tính khóa chung Diffie–Hellman")
                    incoming = recv_msg(reader)
                    if incoming.get("type") != "data":
                        raise ValueError("Bob chờ data nhưng nhận loại tin khác")
                    plaintext = decrypt_message(
                        key, bytes.fromhex(incoming["nonce"]),
                        bytes.fromhex(incoming["ciphertext"]),
                    )
                    log_step("Bob", "05 | GIẢI MÃ TIN NHẮN THÀNH CÔNG", f"Bản rõ: {plaintext}")
                    nonce, ciphertext = encrypt_message(key, "Bob đã nhận: " + plaintext)
                    log_step("Bob", "06 | GỬI PHẢN HỒI ĐÃ MÃ HÓA")
                    send_msg(conn, {
                        "type": "data", "nonce": nonce.hex(), "ciphertext": ciphertext.hex()
                    })
                except (ValueError, KeyError, TypeError) as exc:
                    reason = str(exc)
                    print(f"[Bob] {reason}")
                    try:
                        send_msg(conn, {"type": "error", "reason": reason})
                    except OSError:
                        pass


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Bên Bob (server)")
    parser.add_argument("--port", type=int, default=BOB_PORT)
    parser.add_argument("--auth", action="store_true")
    args = parser.parse_args()
    try:
        run_bob(port=args.port, auth=args.auth)
    except (ValueError, ConnectionError, OSError) as exc:
        print(f"[Bob] Lỗi: {exc}")
        raise SystemExit(1) from None
