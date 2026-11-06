"""
dh_math.py – TV1
Các hàm toán học nền tảng cho Diffie-Hellman:
lũy thừa modulo, kiểm tra số nguyên tố Miller–Rabin, sinh số nguyên tố an toàn
p = 2q + 1 và tìm phần tử sinh g.

Chỉ dùng thư viện chuẩn. Số ngẫu nhiên lấy từ `secrets`, KHÔNG dùng `random`.
Tự chạy thử:  python dh_math.py
"""

import secrets


def _small_primes(limit: int) -> list[int]:
    """Liệt kê các số nguyên tố nhỏ hơn `limit` bằng sàng Eratosthenes."""
    is_prime = bytearray([1]) * limit
    is_prime[0:2] = b"\x00\x00"
    for i in range(2, int(limit ** 0.5) + 1):
        if is_prime[i]:
            is_prime[i * i::i] = bytes(len(range(i * i, limit, i)))
    return [i for i in range(limit) if is_prime[i]]


# Dùng để chia thử trước khi chạy Miller–Rabin (loại nhanh phần lớn hợp số)
SMALL_PRIMES = _small_primes(2000)

# RFC 2409 – Oakley Group 2 (1024 bit), g = 2
RFC2409_GROUP2_P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381"
    "FFFFFFFFFFFFFFFF",
    16,
)

# RFC 3526 – Group 14 (2048 bit), g = 2
RFC3526_GROUP14_P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF",
    16,
)

RFC_GENERATOR = 2


def mod_pow(base: int, exp: int, mod: int) -> int:
    """Tính base^exp mod mod bằng thuật toán bình phương và nhân."""
    if mod <= 0:
        raise ValueError("mod phải là số nguyên dương")
    if exp < 0:
        raise ValueError("exp phải là số không âm")
    if mod == 1:
        return 0

    result = 1
    base %= mod
    while exp > 0:
        if exp & 1:                      # bit thấp nhất của exp là 1
            result = result * base % mod
        base = base * base % mod         # bình phương cho bit kế tiếp
        exp >>= 1
    return result


def _miller_rabin(n: int, rounds: int) -> bool:
    """Chạy `rounds` vòng Miller–Rabin với cơ số ngẫu nhiên (n lẻ, n > 3)."""
    # Viết n - 1 = d * 2^s với d lẻ
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1

    for _ in range(rounds):
        a = 2 + secrets.randbelow(n - 3)     # cơ số a trong [2, n - 2]
        x = mod_pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False                     # a là bằng chứng n là hợp số
    return True


def is_probable_prime(n: int, rounds: int = 40) -> bool:
    """Kiểm tra n có (gần như chắc chắn) là số nguyên tố bằng Miller–Rabin."""
    if n < 2:
        return False
    for sp in SMALL_PRIMES:
        if n == sp:
            return True
        if n % sp == 0:
            return False
    if n < SMALL_PRIMES[-1] ** 2:            # không có ước nhỏ hơn √n -> nguyên tố
        return True
    return _miller_rabin(n, rounds)


def generate_safe_prime(bits: int) -> int:
    """Sinh p = 2q + 1 với p, q đều nguyên tố, p dài đúng `bits` bit."""
    if bits < 16:
        raise ValueError("bits phải từ 16 trở lên")

    q_bits = bits - 1
    window = max(4096, bits * bits // 2)     # số ứng viên q xét trong một lần sàng
    odd_primes = SMALL_PRIMES[1:]            # bỏ số 2 vì q luôn lẻ

    while True:
        # q0 lẻ, có đúng q_bits bit; xét các ứng viên q = q0 + 2k, k = 0..window-1
        q0 = secrets.randbits(q_bits) | (1 << (q_bits - 1)) | 1

        # Sàng: gạch các k làm q hoặc 2q + 1 chia hết cho một số nguyên tố nhỏ r.
        #   q ≡ 0 (mod r)            <=>  k ≡ -q0 * 2⁻¹         (mod r)
        #   2q + 1 ≡ 0 (mod r)       <=>  k ≡ (-1/2 - q0) * 2⁻¹ (mod r)
        candidate = bytearray([1]) * window
        for r in odd_primes:
            inv2 = (r + 1) // 2                  # 2⁻¹ mod r
            c = q0 % r
            for start in ((-c * inv2) % r, ((r - 1) // 2 - c) * inv2 % r):
                candidate[start::r] = bytes(len(range(start, window, r)))

        k = candidate.find(1)
        while k != -1:
            q = q0 + 2 * k
            if q.bit_length() != q_bits:         # vượt quá q_bits bit -> chọn q0 mới
                break
            p = 2 * q + 1
            # Lọc nhanh bằng 1 vòng, qua được mới kiểm tra đủ 40 vòng
            if (_miller_rabin(q, 1) and _miller_rabin(p, 1)
                    and _miller_rabin(q, 40) and _miller_rabin(p, 40)):
                return p
            k = candidate.find(1, k + 1)


def find_generator(p: int) -> int:
    """Tìm g sao cho g² mod p ≠ 1 và g^q mod p ≠ 1, với q = (p - 1) / 2."""
    # Với p = 2q + 1, cấp của g chỉ có thể là 1, 2, q hoặc 2q.
    # Loại cấp 1, 2 (g² ≠ 1) và cấp q (g^q ≠ 1) thì g có cấp 2q = p - 1, tức là phần tử sinh.
    q = (p - 1) // 2
    for g in range(2, p - 1):
        if mod_pow(g, 2, p) != 1 and mod_pow(g, q, p) != 1:
            return g
    raise ValueError("Không tìm thấy phần tử sinh – p có phải số nguyên tố an toàn không?")


def get_params(bits: int = 512) -> tuple[int, int]:
    """Trả về (p, g): 1024 bit dùng RFC 2409 nhóm 2, 2048 bit dùng RFC 3526 nhóm 14, còn lại tự sinh."""
    # Nhóm RFC dùng g = 2, sinh nhóm con cấp q (chuẩn quốc tế, dùng trong IKE/IPsec, SSH).
    if bits == 1024:
        return RFC2409_GROUP2_P, RFC_GENERATOR
    if bits == 2048:
        return RFC3526_GROUP14_P, RFC_GENERATOR
    p = generate_safe_prime(bits)
    return p, find_generator(p)


if __name__ == "__main__":
    import time

    print("== Tự kiểm thử dh_math.py ==")

    # 1. mod_pow phải khớp với pow() có sẵn của Python
    for _ in range(1000):
        m = secrets.randbits(256) + 2
        b, e = secrets.randbits(300), secrets.randbits(300)
        assert mod_pow(b, e, m) == pow(b, e, m)
    assert mod_pow(5, 0, 7) == 1 and mod_pow(5, 3, 1) == 0
    print("[OK] mod_pow khớp pow() trên 1000 bộ số ngẫu nhiên")

    # 2. Miller–Rabin với số nguyên tố / hợp số đã biết
    primes = [2, 3, 5, 97, 7919, 104729, 2**61 - 1, 2**127 - 1]
    composites = [0, 1, 4, 561, 41041, 825265, 3215031751, 2**64 + 1, (2**61 - 1) * (2**31 - 1)]
    assert all(is_probable_prime(n) for n in primes)
    assert not any(is_probable_prime(n) for n in composites)   # có cả số Carmichael 561, 41041
    print("[OK] Miller–Rabin đúng với số nguyên tố, hợp số và số Carmichael")

    # 3. Hằng số RFC là số nguyên tố an toàn đúng độ dài
    for name, bits in (("RFC 2409 nhóm 2", 1024), ("RFC 3526 nhóm 14", 2048)):
        p, g = get_params(bits)
        assert p.bit_length() == bits and is_probable_prime(p) and is_probable_prime((p - 1) // 2)
        print(f"[OK] {name}: p {bits} bit là số nguyên tố an toàn, g = {g}")

    # 4. Sinh p, g
    for bits in (128, 256, 512):
        t = time.perf_counter()
        p, g = get_params(bits)
        dt = time.perf_counter() - t
        q = (p - 1) // 2
        assert p.bit_length() == bits and is_probable_prime(p) and is_probable_prime(q)
        assert mod_pow(g, 2, p) != 1 and mod_pow(g, q, p) != 1
        print(f"[OK] Sinh p {bits} bit, g = {g} trong {dt:.2f} giây")

    print("Tất cả kiểm thử đều qua.")
