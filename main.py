"""
main.py – TV1
Chạy 3 kịch bản demo trong một chương trình, mỗi bên chạy trong một luồng riêng:

    python main.py normal     Trao đổi khóa bình thường
    python main.py mitm       Bị MITM, không có xác thực
    python main.py auth       Bị MITM, có xác thực -> phát hiện

Tùy chọn: --bits 512|1024|2048, --message "..."
"""

import argparse

from channel import BOB_PORT, MALLORY_PORT  # noqa: F401
from alice import run_alice, DEFAULT_MESSAGE  # noqa: F401
from bob import run_bob  # noqa: F401
from mallory import run_mallory  # noqa: F401
from dh_auth import generate_signing_keys, load_private_key, load_public_key  # noqa: F401


def scenario_normal(bits: int, message: str) -> None:
    """Alice nói chuyện thẳng với Bob (cổng 5000)."""
    # TODO(TV1): chạy Bob trong luồng riêng, đợi Bob mở cổng, chạy Alice tới BOB_PORT.
    raise NotImplementedError("TV1: scenario_normal chưa cài đặt")


def scenario_mitm(bits: int, message: str) -> None:
    """Alice -> Mallory (5001) -> Bob (5000), không có xác thực."""
    # TODO(TV1): chạy Bob, Mallory trong luồng riêng, chạy Alice tới MALLORY_PORT.
    raise NotImplementedError("TV1: scenario_mitm chưa cài đặt")


def scenario_auth(bits: int, message: str) -> None:
    """Như mitm nhưng bật chữ ký RSA: Bob phải phát hiện MITM."""
    # TODO(TV1): sinh khóa RSA cho alice/bob nếu chưa có, rồi chạy như mitm với auth=True.
    raise NotImplementedError("TV1: scenario_auth chưa cài đặt")


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


if __name__ == "__main__":
    main()
