"""
main.py – TV1
Chạy 3 kịch bản demo trong một chương trình, mỗi bên chạy trong một luồng riêng:

    python main.py normal     Trao đổi khóa bình thường
    python main.py mitm       Bị MITM, không có xác thực
    python main.py auth       Bị MITM, có xác thực -> phát hiện

Tùy chọn: --bits 512|1024|2048, --message "..."
"""

import argparse
import sys
import threading
import time

from channel import BOB_PORT, MALLORY_PORT
from alice import run_alice, DEFAULT_MESSAGE
from bob import run_bob
from mallory import run_mallory
from dh_auth import generate_signing_keys, load_private_key, load_public_key

SERVER_START_DELAY = 0.5  # giây: chờ Bob/Mallory mở cổng rồi Alice mới kết nối
THREAD_TIMEOUT = 15       # giây: chờ tối đa Bob/Mallory kết thúc sau khi Alice xong

# Ghi lại lỗi xảy ra trong các bên để cuối chương trình báo tổng kết
_errors: list[str] = []


def print_banner(title: str, expected: str) -> None:
    """In tiêu đề kịch bản và kết quả mong đợi."""
    line = "=" * 70
    print(f"\n{line}\n  KỊCH BẢN: {title}\n  Mong đợi: {expected}\n{line}\n")


def _record_error(name: str, exc: Exception) -> None:
    """In lỗi của một bên và ghi lại để tổng kết."""
    _errors.append(f"{name}: {type(exc).__name__}: {exc}")
    print(f"[{name}] Lỗi: {type(exc).__name__}: {exc}")


def start_in_thread(name: str, func, **kwargs) -> threading.Thread:
    """Chạy func(**kwargs) trong một luồng nền; lỗi trong luồng được in ra thay vì bị nuốt mất."""
    def target():
        try:
            func(**kwargs)
        except Exception as exc:  # noqa: BLE001 – demo: in mọi lỗi cho dễ thấy
            _record_error(name, exc)

    thread = threading.Thread(target=target, name=name, daemon=True)
    thread.start()
    return thread


def ensure_signing_keys() -> None:
    """Sinh khóa RSA cho alice và bob nếu trong keys/ chưa có."""
    for name in ("alice", "bob"):
        try:
            load_private_key(name)
            load_public_key(name)
        except FileNotFoundError:
            print(f"[main] Chưa có khóa RSA của {name}, đang sinh khóa mới...")
            generate_signing_keys(name)


def run_scenario(alice_port: int, auth: bool, with_mallory: bool, bits: int, message: str) -> None:
    """Khởi động Bob (và Mallory nếu có) trong luồng riêng, rồi chạy Alice ở luồng chính."""
    threads = [start_in_thread("Bob", run_bob, port=BOB_PORT, auth=auth)]
    if with_mallory:
        threads.append(start_in_thread("Mallory", run_mallory,
                                       listen_port=MALLORY_PORT, bob_port=BOB_PORT))
    time.sleep(SERVER_START_DELAY)

    alice_ok = True
    try:
        run_alice(port=alice_port, auth=auth, bits=bits, message=message)
    except Exception as exc:  # noqa: BLE001
        alice_ok = False
        _record_error("Alice", exc)

    # Alice lỗi thì Bob/Mallory có thể đang kẹt ở accept(), không cần chờ lâu
    timeout = THREAD_TIMEOUT if alice_ok else 1
    for thread in threads:
        thread.join(timeout=timeout)
        if thread.is_alive():
            print(f"[main] Cảnh báo: {thread.name} chưa kết thúc sau {timeout} giây")


def scenario_normal(bits: int, message: str) -> None:
    """Alice nói chuyện thẳng với Bob (cổng 5000)."""
    print_banner("normal – Alice nói chuyện thẳng với Bob",
                 "Alice và Bob tính ra cùng một khóa, Bob đọc đúng tin nhắn")
    run_scenario(alice_port=BOB_PORT, auth=False, with_mallory=False, bits=bits, message=message)


def scenario_mitm(bits: int, message: str) -> None:
    """Alice -> Mallory (5001) -> Bob (5000), không có xác thực."""
    print_banner("mitm – Mallory đứng giữa, KHÔNG có xác thực",
                 "Mallory đọc và sửa được tin nhắn, Bob nhận tin đã bị sửa mà không biết")
    run_scenario(alice_port=MALLORY_PORT, auth=False, with_mallory=True, bits=bits, message=message)


def scenario_auth(bits: int, message: str) -> None:
    """Như mitm nhưng bật chữ ký RSA: Bob phải phát hiện MITM."""
    print_banner("auth – Mallory đứng giữa, CÓ xác thực bằng chữ ký RSA",
                 "Mallory không làm giả được chữ ký, Bob báo \"Phát hiện MITM\" và ngắt kết nối")
    ensure_signing_keys()
    run_scenario(alice_port=MALLORY_PORT, auth=True, with_mallory=True, bits=bits, message=message)


SCENARIOS = {
    "normal": scenario_normal,
    "mitm": scenario_mitm,
    "auth": scenario_auth,
}


def main() -> None:
    parser = argparse.ArgumentParser(description="Demo Diffie-Hellman và tấn công MITM")
    parser.add_argument("scenario", choices=SCENARIOS.keys(), help="kịch bản cần chạy")
    parser.add_argument("--bits", type=int, default=512, help="độ dài p (bit), mặc định 512")
    parser.add_argument("--message", default=DEFAULT_MESSAGE, help="tin nhắn Alice gửi cho Bob")
    args = parser.parse_args()

    SCENARIOS[args.scenario](args.bits, args.message)

    print("\n" + "-" * 70)
    if _errors:
        print(f"[main] Kết thúc với {len(_errors)} lỗi:")
        for err in _errors:
            print(f"  - {err}")
        sys.exit(1)
    print("[main] Kết thúc kịch bản, không có lỗi chương trình.")


if __name__ == "__main__":
    main()
