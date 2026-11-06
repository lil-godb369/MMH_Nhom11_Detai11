"""
benchmark.py – TV4
Đo thời gian sinh khóa và tính khóa chung Diffie-Hellman theo độ dài p.

Chạy riêng:  python benchmark.py [--runs 20]
"""

import argparse
import time  # noqa: F401  (dùng khi cài đặt)

from dh_math import get_params  # noqa: F401
from dh_protocol import generate_private_key, compute_public_key, compute_shared_secret  # noqa: F401


def run_benchmark(bits_list=(512, 1024, 2048), runs: int = 20) -> list[dict]:
    """Đo thời gian sinh khóa và tính khóa chung cho từng độ dài p, in bảng kết quả."""
    # TODO(TV4):
    #   Với mỗi bits trong bits_list:
    #     - p, g = get_params(bits)   (đo riêng, không gộp vào thời gian sinh khóa)
    #     - lặp `runs` lần, dùng time.perf_counter() đo:
    #         + sinh khóa: generate_private_key + compute_public_key
    #         + tính khóa chung: compute_shared_secret
    #     - lưu trung bình (ms) vào dict, vd {"bits": 512, "keygen_ms": ..., "shared_ms": ...}
    #   In bảng kết quả, trả về list các dict.
    raise NotImplementedError("TV4: run_benchmark chưa cài đặt")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Đo thời gian Diffie-Hellman theo độ dài p")
    parser.add_argument("--runs", type=int, default=20, help="số lần lặp cho mỗi độ dài")
    args = parser.parse_args()
    run_benchmark(runs=args.runs)
