"""
benchmark.py – TV4
Đo thời gian sinh khóa và tính khóa chung Diffie-Hellman theo độ dài p.
Đo thêm thời gian ký và xác minh chữ ký RSA, để so sánh có và không có xác thực.

Chạy riêng:  python benchmark.py [--runs 20] [--bits 512 1024 2048]
"""

import argparse
import time

from dh_math import get_params
from dh_protocol import generate_private_key, compute_public_key, compute_shared_secret
from dh_auth import (
    generate_signing_keys,
    load_private_key,
    load_public_key,
    sign_dh_public,
    verify_dh_public,
)


def _elapsed_ms(start: float) -> float:
    """Số mili giây đã trôi qua kể từ mốc `start` (lấy từ time.perf_counter())."""
    return (time.perf_counter() - start) * 1000


def _load_alice_keys():
    """Lấy khóa RSA của alice (chưa có thì sinh mới) để đo thời gian ký và xác minh."""
    try:
        return load_private_key("alice"), load_public_key("alice")
    except FileNotFoundError:
        generate_signing_keys("alice")
        return load_private_key("alice"), load_public_key("alice")


def _measure(bits: int, runs: int, rsa_private, rsa_public) -> dict:
    """Đo một độ dài p: lặp `runs` lần rồi trả về dict thời gian trung bình (ms).
    Khóa công khai B của bên kia được tạo ngoài thời gian bấm giờ."""
    start = time.perf_counter()
    p, g = get_params(bits)
    params_ms = _elapsed_ms(start)

    keygen_total = shared_total = sign_total = verify_total = 0.0

    for _ in range(runs):
        start = time.perf_counter()
        a = generate_private_key(p)
        A = compute_public_key(g, a, p)
        keygen_total += _elapsed_ms(start)

        B = compute_public_key(g, generate_private_key(p), p)

        start = time.perf_counter()
        compute_shared_secret(B, a, p)
        shared_total += _elapsed_ms(start)

        start = time.perf_counter()
        signature = sign_dh_public(rsa_private, p, g, A)
        sign_total += _elapsed_ms(start)

        start = time.perf_counter()
        verify_dh_public(rsa_public, p, g, A, signature)
        verify_total += _elapsed_ms(start)

    keygen_ms = keygen_total / runs
    shared_ms = shared_total / runs
    sign_ms = sign_total / runs
    verify_ms = verify_total / runs

    no_auth_ms = keygen_ms + shared_ms
    auth_ms = no_auth_ms + sign_ms + verify_ms
    overhead_pct = (auth_ms - no_auth_ms) / no_auth_ms * 100

    return {
        "bits": bits,
        "params_ms": params_ms,
        "keygen_ms": keygen_ms,
        "shared_ms": shared_ms,
        "sign_ms": sign_ms,
        "verify_ms": verify_ms,
        "no_auth_ms": no_auth_ms,
        "auth_ms": auth_ms,
        "overhead_pct": overhead_pct,
    }


def _print_tables(results: list[dict], runs: int) -> None:
    """In 2 bảng kết quả: thời gian từng bước, và so sánh có / không có xác thực."""
    line = "-" * 74

    print(f"\nBẢNG 1 – Thời gian từng bước, trung bình của {runs} lần đo (đơn vị: ms)")
    print(line)
    print(f"{'p (bit)':>8} | {'Lấy p, g':>10} | {'Sinh khóa':>10} | {'Khóa chung':>11} | "
          f"{'Ký RSA':>8} | {'Xác minh':>9}")
    print(line)
    for r in results:
        print(f"{r['bits']:>8} | {r['params_ms']:>10.2f} | {r['keygen_ms']:>10.3f} | "
              f"{r['shared_ms']:>11.3f} | {r['sign_ms']:>8.3f} | {r['verify_ms']:>9.3f}")
    print(line)
    print("Ghi chú: 1024 và 2048 bit lấy p từ hằng số RFC nên 'Lấy p, g' gần như bằng 0;"
          " 512 bit phải tự sinh\nsố nguyên tố nên mỗi lần chạy lâu mau khác nhau.")

    print("\nBẢNG 2 – Chi phí của xác thực cho mỗi bên (đơn vị: ms)")
    print(line)
    print(f"{'p (bit)':>8} | {'Không xác thực':>15} | {'Có xác thực':>12} | {'Thêm (ms)':>10} | {'Thêm (%)':>9}")
    print(line)
    for r in results:
        print(f"{r['bits']:>8} | {r['no_auth_ms']:>15.3f} | {r['auth_ms']:>12.3f} | "
              f"{r['auth_ms'] - r['no_auth_ms']:>10.3f} | {r['overhead_pct']:>8.1f}%")
    print(line)
    print("Ghi chú: Không xác thực = sinh khóa + tính khóa chung; Có xác thực = thêm 1 lần ký + 1 lần xác minh.")


def run_benchmark(bits_list=(512, 1024, 2048), runs: int = 20) -> list[dict]:
    """Đo thời gian sinh khóa và tính khóa chung cho từng độ dài p, in bảng kết quả.
    Chạy thử ký 1 lần trước khi bấm giờ vì lần gọi đầu tiên thường chậm hơn."""
    if runs < 1:
        raise ValueError("runs phải từ 1 trở lên")

    rsa_private, rsa_public = _load_alice_keys()
    sign_dh_public(rsa_private, 1, 1, 1)

    results = []
    for bits in bits_list:
        print(f"[benchmark] Đang đo p {bits} bit ({runs} lần)...", flush=True)
        results.append(_measure(bits, runs, rsa_private, rsa_public))

    _print_tables(results, runs)
    return results


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Đo thời gian Diffie-Hellman theo độ dài p")
    parser.add_argument("--runs", type=int, default=20, help="số lần lặp cho mỗi độ dài")
    parser.add_argument("--bits", type=int, nargs="+", default=[512, 1024, 2048],
                        help="các độ dài p cần đo, vd: --bits 1024 2048")
    args = parser.parse_args()
    run_benchmark(bits_list=args.bits, runs=args.runs)