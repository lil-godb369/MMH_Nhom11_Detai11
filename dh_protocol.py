"""
dh_protocol.py – TV1
Các bước của giao thức Diffie-Hellman và mã hóa tin nhắn:
sinh khóa riêng/khóa công khai, tính khóa chung, tạo khóa AES-256 từ khóa chung,
mã hóa và giải mã tin nhắn bằng AES-256-GCM.

Trong lúc file này chưa xong, các bạn tạm dùng pow(g, a, p) có sẵn để thử.
"""

import hashlib  # noqa: F401  (dùng khi cài đặt)
import secrets  # noqa: F401

from dh_math import mod_pow  # noqa: F401

NONCE_SIZE = 12  # byte, độ dài nonce chuẩn của AES-GCM


def generate_private_key(p: int) -> int:
    """Sinh khóa riêng: số ngẫu nhiên trong đoạn [2, p − 2]."""
    # TODO(TV1): dùng secrets.randbelow
    raise NotImplementedError("TV1: generate_private_key chưa cài đặt")


def compute_public_key(g: int, private_key: int, p: int) -> int:
    """Tính khóa công khai g^a mod p."""
    raise NotImplementedError("TV1: compute_public_key chưa cài đặt")


def compute_shared_secret(other_public: int, private_key: int, p: int) -> int:
    """Tính khóa chung B^a mod p từ khóa công khai của bên kia."""
    raise NotImplementedError("TV1: compute_shared_secret chưa cài đặt")


def is_valid_public_key(value: int, p: int) -> bool:
    """Kiểm tra 2 ≤ value ≤ p − 2, chặn khóa công khai bất thường (0, 1, p − 1...)."""
    raise NotImplementedError("TV1: is_valid_public_key chưa cài đặt")


def derive_aes_key(shared_secret: int) -> bytes:
    """Băm khóa chung bằng SHA-256, ra khóa AES-256 (32 byte)."""
    raise NotImplementedError("TV1: derive_aes_key chưa cài đặt")


def encrypt_message(key: bytes, plaintext: str) -> tuple[bytes, bytes]:
    """Mã hóa AES-256-GCM với nonce 12 byte ngẫu nhiên, trả về (nonce, ciphertext)."""
    raise NotImplementedError("TV1: encrypt_message chưa cài đặt")


def decrypt_message(key: bytes, nonce: bytes, ciphertext: bytes) -> str:
    """Giải mã AES-256-GCM; báo ValueError nếu sai khóa hoặc tin nhắn bị sửa trên đường truyền."""
    raise NotImplementedError("TV1: decrypt_message chưa cài đặt")


if __name__ == "__main__":
    # TODO(TV1): giả lập Alice và Bob trong bộ nhớ, kiểm tra hai bên ra cùng
    #            khóa, mã hóa/giải mã đúng, sửa 1 byte thì giải mã báo lỗi.
    print("dh_protocol.py: chưa có phần tự kiểm thử")
