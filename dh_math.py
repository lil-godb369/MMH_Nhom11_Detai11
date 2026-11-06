"""
dh_math.py – TV1
Các hàm toán học nền tảng cho Diffie-Hellman:
lũy thừa modulo, kiểm tra số nguyên tố Miller–Rabin, sinh số nguyên tố an toàn
p = 2q + 1 và tìm phần tử sinh g.

Chỉ dùng thư viện chuẩn. Số ngẫu nhiên lấy từ `secrets`, KHÔNG dùng `random`.
"""

import secrets  # noqa: F401  (dùng khi cài đặt)


def mod_pow(base: int, exp: int, mod: int) -> int:
    """Tính base^exp mod mod bằng thuật toán bình phương và nhân."""
    # TODO(TV1): duyệt từng bit của exp, bit = 1 thì nhân result với base,
    #            mỗi vòng bình phương base, luôn lấy mod để số không phình to.
    raise NotImplementedError("TV1: mod_pow chưa cài đặt")


def is_probable_prime(n: int, rounds: int = 40) -> bool:
    """Kiểm tra n có (gần như chắc chắn) là số nguyên tố bằng Miller–Rabin."""
    # TODO(TV1): chia thử cho các số nguyên tố nhỏ, rồi viết n - 1 = d * 2^s
    #            và chạy `rounds` vòng Miller–Rabin với cơ số ngẫu nhiên.
    raise NotImplementedError("TV1: is_probable_prime chưa cài đặt")


def generate_safe_prime(bits: int) -> int:
    """Sinh p = 2q + 1 với p, q đều nguyên tố, p dài đúng `bits` bit."""
    # TODO(TV1): chọn q ngẫu nhiên (bits - 1) bit, lọc nhanh bằng số nguyên tố
    #            nhỏ, rồi kiểm tra q và 2q + 1 bằng Miller–Rabin.
    raise NotImplementedError("TV1: generate_safe_prime chưa cài đặt")


def find_generator(p: int) -> int:
    """Tìm g sao cho g² mod p ≠ 1 và g^q mod p ≠ 1, với q = (p - 1) / 2."""
    # TODO(TV1): thử g = 2, 3, 4, ... cho tới khi thỏa điều kiện.
    raise NotImplementedError("TV1: find_generator chưa cài đặt")


def get_params(bits: int = 512) -> tuple[int, int]:
    """Trả về (p, g): 1024 bit dùng RFC 2409 nhóm 2, 2048 bit dùng RFC 3526 nhóm 14, còn lại tự sinh."""
    # TODO(TV1): khai báo hằng số p của RFC, các độ dài khác thì gọi
    #            generate_safe_prime(bits) và find_generator(p).
    raise NotImplementedError("TV1: get_params chưa cài đặt")


if __name__ == "__main__":
    # TODO(TV1): tự kiểm thử – so mod_pow với pow() có sẵn, thử Miller–Rabin
    #            với vài số nguyên tố/hợp số đã biết, sinh thử p nhỏ.
    print("dh_math.py: chưa có phần tự kiểm thử")
