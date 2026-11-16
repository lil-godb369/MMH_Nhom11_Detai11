"""
dh_auth.py – TV4
Xác thực khóa công khai Diffie-Hellman bằng chữ ký RSA-PSS + SHA-256.
Giả định Alice và Bob đã có sẵn khóa công khai RSA của nhau từ trước (giống chứng chỉ).

Khóa lưu trong keys/<name>_private.pem và keys/<name>_public.pem (KHÔNG đẩy lên repo).
Chạy riêng:  python dh_auth.py   -> sinh khóa cho alice, bob, mallory rồi tự kiểm thử
"""

import os

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

KEYS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "keys")
RSA_KEY_SIZE = 2048


def _key_path(name: str, kind: str) -> str:
    """Đường dẫn file khóa, vd _key_path("alice", "private") -> keys/alice_private.pem."""
    return os.path.join(KEYS_DIR, f"{name}_{kind}.pem")


def _pss_padding():
    """Kiểu đệm RSA-PSS (SHA-256) dùng chung cho cả ký và xác minh."""
    return padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)


def _dh_message(p: int, g: int, public_value: int) -> bytes:
    """Dựng chuỗi cần ký f"{p}|{g}|{public_value}"; hai bên phải dựng giống hệt nhau."""
    return f"{p}|{g}|{public_value}".encode("utf-8")


def generate_signing_keys(name: str) -> None:
    """Sinh cặp khóa RSA 2048 bit, lưu vào keys/<name>_private.pem và keys/<name>_public.pem."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=RSA_KEY_SIZE)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    os.makedirs(KEYS_DIR, exist_ok=True)
    with open(_key_path(name, "private"), "wb") as f:
        f.write(private_pem)
    with open(_key_path(name, "public"), "wb") as f:
        f.write(public_pem)


def load_private_key(name: str):
    """Đọc khóa riêng RSA từ keys/<name>_private.pem (chưa có file thì báo FileNotFoundError)."""
    with open(_key_path(name, "private"), "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def load_public_key(name: str):
    """Đọc khóa công khai RSA từ keys/<name>_public.pem (chưa có file thì báo FileNotFoundError)."""
    with open(_key_path(name, "public"), "rb") as f:
        return serialization.load_pem_public_key(f.read())


def sign_dh_public(private_key, p: int, g: int, public_value: int) -> bytes:
    """Ký chuỗi f"{p}|{g}|{public_value}" bằng RSA-PSS + SHA-256, trả về chữ ký."""
    return private_key.sign(_dh_message(p, g, public_value), _pss_padding(), hashes.SHA256())


def verify_dh_public(public_key, p: int, g: int, public_value: int, signature: bytes) -> bool:
    """Trả về True nếu chữ ký đúng, False nếu sai hoặc không phải bytes.
    Bắt InvalidSignature để lỗi không văng ra ngoài."""
    if not isinstance(signature, (bytes, bytearray)):
        return False
    try:
        public_key.verify(bytes(signature), _dh_message(p, g, public_value),
                          _pss_padding(), hashes.SHA256())
    except InvalidSignature:
        return False
    return True


def _self_test() -> None:
    """Sinh khóa, kiểm tra ký và xác minh đúng sai, rồi mô phỏng Mallory đổi khóa công khai."""
    from dh_math import get_params
    from dh_protocol import generate_private_key, compute_public_key

    print("== Tự kiểm thử dh_auth.py ==")

    for name in ("alice", "bob", "mallory"):
        generate_signing_keys(name)
        assert os.path.exists(_key_path(name, "private")) and os.path.exists(_key_path(name, "public"))
    alice_priv, alice_pub = load_private_key("alice"), load_public_key("alice")
    bob_priv, bob_pub = load_private_key("bob"), load_public_key("bob")
    mallory_priv = load_private_key("mallory")
    assert alice_priv.public_key().public_numbers() == alice_pub.public_numbers()
    assert alice_pub.key_size == RSA_KEY_SIZE
    print(f"[OK] Sinh và đọc lại khóa RSA {RSA_KEY_SIZE} bit cho alice, bob, mallory (thư mục keys/)")

    try:
        load_private_key("khong_ton_tai")
    except FileNotFoundError:
        print("[OK] Khóa chưa tồn tại -> báo FileNotFoundError")
    else:
        raise AssertionError("load_private_key phải báo FileNotFoundError khi chưa có khóa")

    p, g = get_params(1024)
    a = generate_private_key(p)
    A = compute_public_key(g, a, p)

    signature = sign_dh_public(alice_priv, p, g, A)
    assert isinstance(signature, bytes) and len(signature) == RSA_KEY_SIZE // 8
    assert verify_dh_public(alice_pub, p, g, A, signature) is True
    print(f"[OK] Alice ký khóa công khai A, Bob xác minh bằng khóa công khai của Alice -> True "
          f"(chữ ký {len(signature)} byte)")

    assert verify_dh_public(alice_pub, p, g, A + 1, signature) is False
    print("[OK] Sửa khóa công khai (A + 1) -> False")
    assert verify_dh_public(alice_pub, p + 2, g, A, signature) is False
    assert verify_dh_public(alice_pub, p, g + 1, A, signature) is False
    print("[OK] Sửa p hoặc g -> False (vì thế phải ký cả p, g chứ không chỉ khóa công khai)")
    assert verify_dh_public(bob_pub, p, g, A, signature) is False
    print("[OK] Dùng nhầm khóa công khai của người khác (bob) để xác minh -> False")
    forged = sign_dh_public(mallory_priv, p, g, A)
    assert verify_dh_public(alice_pub, p, g, A, forged) is False
    print("[OK] Chữ ký do Mallory ký bằng khóa riêng của Mallory -> False")
    for rac in (b"\x00" * 256, b"abc", b"", None, signature.hex()):
        assert verify_dh_public(alice_pub, p, g, A, rac) is False
    print("[OK] Chữ ký rác (sai nội dung, sai độ dài, rỗng, None, chuỗi hex chưa đổi về bytes) -> False")

    sig1, sig2 = sign_dh_public(alice_priv, p, g, A), sign_dh_public(alice_priv, p, g, A)
    assert sig1 != sig2 and verify_dh_public(alice_pub, p, g, A, sig1) and verify_dh_public(alice_pub, p, g, A, sig2)
    print("[OK] Ký 2 lần cùng một nội dung ra 2 chữ ký khác nhau, cả hai đều xác minh đúng")

    assert verify_dh_public(alice_pub, p, g, A, bytes.fromhex(signature.hex())) is True
    print("[OK] Đổi chữ ký bytes <-> hex khi gửi qua mạng không làm hỏng chữ ký")

    b = generate_private_key(p)
    B = compute_public_key(g, b, p)
    m = generate_private_key(p)
    M = compute_public_key(g, m, p)

    sig_A = sign_dh_public(alice_priv, p, g, A)
    assert verify_dh_public(alice_pub, p, g, A, sig_A)
    assert not verify_dh_public(alice_pub, p, g, M, sig_A)
    assert not verify_dh_public(alice_pub, p, g, M, sign_dh_public(mallory_priv, p, g, M))
    print("[OK] Bước 1 (Alice -> Bob): Mallory đổi A thành M dù giữ chữ ký cũ hay tự ký -> Bob phát hiện MITM")

    sig_B = sign_dh_public(bob_priv, p, g, B)
    assert verify_dh_public(bob_pub, p, g, B, sig_B)
    assert not verify_dh_public(bob_pub, p, g, M, sig_B)
    assert not verify_dh_public(bob_pub, p, g, M, sign_dh_public(mallory_priv, p, g, M))
    print("[OK] Bước 2 (Bob -> Alice): Mallory đổi B thành M -> Alice phát hiện MITM")

    print("Tất cả kiểm thử đều qua.")


if __name__ == "__main__":
    _self_test()