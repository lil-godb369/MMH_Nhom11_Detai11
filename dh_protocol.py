"""
dh_protocol.py – TV1
Các bước của giao thức Diffie-Hellman và mã hóa tin nhắn:
sinh khóa riêng/khóa công khai, tính khóa chung, tạo khóa AES-256 từ khóa chung,
mã hóa và giải mã tin nhắn bằng AES-256-GCM.

Phần Diffie-Hellman tự viết (dựa trên dh_math.mod_pow); thư viện `cryptography`
chỉ dùng cho AES-GCM.
Tự chạy thử:  python dh_protocol.py
"""

import hashlib
import secrets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from dh_math import mod_pow, is_probable_prime, RFC2409_GROUP2_P, RFC3526_GROUP14_P

NONCE_SIZE = 12  # byte, độ dài nonce chuẩn của AES-GCM
MIN_P_BITS = 512  # độ dài p tối thiểu bên nhận chấp nhận

# Các p đã biết chắc là số nguyên tố an toàn (hằng số RFC) -> bỏ qua Miller–Rabin.
# Kiểm tra p 2048 bit bằng Miller–Rabin tự viết mất khoảng 2 giây, quá chậm cho mỗi lần bắt tay.
_KNOWN_SAFE_PRIMES = frozenset((RFC2409_GROUP2_P, RFC3526_GROUP14_P))


def is_valid_params(p: int, g: int, min_bits: int = MIN_P_BITS) -> bool:
    """Kiểm tra tham số DH nhận được: p là số nguyên tố an toàn ≥ min_bits bit, 2 ≤ g ≤ p − 2, g² mod p ≠ 1."""
    # Chặn kẻ gian gửi p nhỏ / p hợp số / p − 1 nhiều ước nhỏ (tấn công nhóm con nhỏ).
    for x in (p, g):
        if not isinstance(x, int) or isinstance(x, bool):
            return False
    if p.bit_length() < min_bits or not 2 <= g <= p - 2:
        return False
    if p not in _KNOWN_SAFE_PRIMES:
        if not (is_probable_prime(p) and is_probable_prime((p - 1) // 2)):
            return False
    return mod_pow(g, 2, p) != 1


def generate_private_key(p: int) -> int:
    """Sinh khóa riêng: số ngẫu nhiên trong đoạn [2, p − 2]."""
    if p < 5:
        raise ValueError("p quá nhỏ")
    return 2 + secrets.randbelow(p - 3)      # randbelow(p - 3) cho 0..p-4


def compute_public_key(g: int, private_key: int, p: int) -> int:
    """Tính khóa công khai g^a mod p."""
    return mod_pow(g, private_key, p)


def compute_shared_secret(other_public: int, private_key: int, p: int) -> int:
    """Tính khóa chung B^a mod p từ khóa công khai của bên kia."""
    if not is_valid_public_key(other_public, p):
        raise ValueError("Khóa công khai của bên kia không hợp lệ")
    return mod_pow(other_public, private_key, p)


def is_valid_public_key(value: int, p: int) -> bool:
    """Kiểm tra 2 ≤ value ≤ p − 2, chặn khóa công khai bất thường (0, 1, p − 1...)."""
    # Nếu kẻ gian gửi 1 hoặc p − 1 thì khóa chung chỉ có thể là 1 hoặc ±1 -> đoán được ngay.
    return isinstance(value, int) and not isinstance(value, bool) and 2 <= value <= p - 2


def derive_aes_key(shared_secret: int, p: int) -> bytes:
    """Băm khóa chung bằng SHA-256, ra khóa AES-256 (32 byte).
    Khóa chung đổi sang bytes dài cố định bằng độ dài byte của p (NIST SP 800-56A)."""
    # Độ dài cố định: khóa chung có byte đầu bằng 0 vẫn ra cùng chuỗi bytes ở hai bên.
    length = (p.bit_length() + 7) // 8
    return hashlib.sha256(shared_secret.to_bytes(length, "big")).digest()


def encrypt_message(key: bytes, plaintext: str) -> tuple[bytes, bytes]:
    """Mã hóa AES-256-GCM với nonce 12 byte ngẫu nhiên, trả về (nonce, ciphertext)."""
    nonce = secrets.token_bytes(NONCE_SIZE)  # mỗi tin nhắn một nonce mới, không dùng lại
    ciphertext = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), None)
    return nonce, ciphertext                 # ciphertext đã gồm 16 byte tag xác thực ở cuối


def decrypt_message(key: bytes, nonce: bytes, ciphertext: bytes) -> str:
    """Giải mã AES-256-GCM; báo ValueError nếu sai khóa hoặc tin nhắn bị sửa trên đường truyền."""
    try:
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, None)
    except InvalidTag:
        raise ValueError("Giải mã thất bại: sai khóa hoặc tin nhắn đã bị sửa trên đường truyền") from None
    return plaintext.decode("utf-8")


if __name__ == "__main__":
    import sys
    if hasattr(sys.stdout, "reconfigure"):   # Windows: tránh lỗi cp1252 khi lưu output ra file
        sys.stdout.reconfigure(encoding="utf-8")
    from dh_math import get_params

    print("== Tự kiểm thử dh_protocol.py ==")

    for bits in (512, 1024, 2048):
        p, g = get_params(bits)

        # Alice và Bob mỗi người sinh khóa riêng, trao đổi khóa công khai
        a = generate_private_key(p)
        b = generate_private_key(p)
        assert 2 <= a <= p - 2 and 2 <= b <= p - 2
        A = compute_public_key(g, a, p)
        B = compute_public_key(g, b, p)
        assert A == pow(g, a, p) and B == pow(g, b, p)
        assert is_valid_public_key(A, p) and is_valid_public_key(B, p)

        s_alice = compute_shared_secret(B, a, p)
        s_bob = compute_shared_secret(A, b, p)
        assert s_alice == s_bob
        key_alice, key_bob = derive_aes_key(s_alice, p), derive_aes_key(s_bob, p)
        assert key_alice == key_bob and len(key_alice) == 32
        print(f"[OK] p {bits} bit: Alice và Bob ra cùng khóa AES {key_alice.hex()[:16]}...")

    # Mã hóa / giải mã tiếng Việt có dấu
    msg = "Chuyển 100.000đ vào tài khoản của Bob"
    nonce, ct = encrypt_message(key_alice, msg)
    assert len(nonce) == NONCE_SIZE and decrypt_message(key_bob, nonce, ct) == msg
    nonce2, _ = encrypt_message(key_alice, msg)
    assert nonce2 != nonce
    print("[OK] Mã hóa/giải mã AES-256-GCM đúng, mỗi lần một nonce khác nhau")

    # Gửi qua mạng dạng hex rồi đổi lại
    assert decrypt_message(key_bob, bytes.fromhex(nonce.hex()), bytes.fromhex(ct.hex())) == msg
    print("[OK] Đổi bytes <-> hex khi gửi qua mạng không làm hỏng dữ liệu")

    # Sửa 1 byte ciphertext, hoặc dùng sai khóa -> phải báo lỗi
    tampered = bytearray(ct)
    tampered[0] ^= 0x01
    for bad_key, bad_ct, what in ((key_bob, bytes(tampered), "sửa 1 byte"),
                                  (secrets.token_bytes(32), ct, "sai khóa")):
        try:
            decrypt_message(bad_key, nonce, bad_ct)
        except ValueError:
            print(f"[OK] Phát hiện tin nhắn không hợp lệ ({what})")
        else:
            raise AssertionError(f"Không phát hiện được: {what}")

    # Chặn khóa công khai bất thường
    for bad in (0, 1, p - 1, p, -5, True):
        assert not is_valid_public_key(bad, p)
    try:
        compute_shared_secret(1, a, p)
    except ValueError:
        print("[OK] Chặn khóa công khai bất thường (0, 1, p − 1, p...)")
    else:
        raise AssertionError("compute_shared_secret chấp nhận khóa công khai = 1")

    # derive_aes_key: khóa chung đổi sang bytes dài cố định bằng độ dài byte của p
    p_len = (p.bit_length() + 7) // 8
    assert derive_aes_key(5, p) == hashlib.sha256((5).to_bytes(p_len, "big")).digest()
    assert derive_aes_key(5, p) != hashlib.sha256(b"\x05").digest()
    print(f"[OK] derive_aes_key dùng độ dài cố định {p_len} byte (theo p), kể cả khi khóa chung nhỏ")

    # is_valid_params: nhận nhóm RFC và p tự sinh, chặn p yếu / g yếu
    import time
    from dh_math import generate_safe_prime, RFC_GENERATOR

    for p_ok in (RFC2409_GROUP2_P, RFC3526_GROUP14_P):
        t = time.perf_counter()
        assert is_valid_params(p_ok, RFC_GENERATOR)
        print(f"[OK] is_valid_params nhận nhóm RFC {p_ok.bit_length()} bit "
              f"trong {time.perf_counter() - t:.4f} giây")
    p512, g512 = get_params(512)
    t = time.perf_counter()
    assert is_valid_params(p512, g512)
    print(f"[OK] is_valid_params nhận p 512 bit tự sinh trong {time.perf_counter() - t:.3f} giây")

    p_small = generate_safe_prime(256)                 # an toàn nhưng quá ngắn
    assert not is_valid_params(p_small, 2)
    assert is_valid_params(p_small, 2, min_bits=256)
    not_safe = p512 + 2                                # số nguyên tố 512 bit nhưng (p − 1)/2 là hợp số
    while not (is_probable_prime(not_safe) and not is_probable_prime((not_safe - 1) // 2)):
        not_safe += 2
    composite = p512 + 2                               # hợp số lẻ 512 bit
    while is_probable_prime(composite):
        composite += 2
    for bad_p in (not_safe, composite):
        assert bad_p.bit_length() == 512 and not is_valid_params(bad_p, 2)
    for bad_g in (0, 1, p512 - 1, p512, -2, True):
        assert not is_valid_params(p512, bad_g)
    for bad_p in (True, 23, "123", None, float(p512)):
        assert not is_valid_params(bad_p, 2)
    print("[OK] is_valid_params chặn p quá ngắn, p không phải số nguyên tố an toàn, g = 0, 1, p − 1, bool...")

    print("Tất cả kiểm thử đều qua.")
