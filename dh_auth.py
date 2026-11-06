"""
dh_auth.py – TV4
Xác thực khóa công khai Diffie-Hellman bằng chữ ký RSA-PSS + SHA-256.
Giả định Alice và Bob đã có sẵn khóa công khai RSA của nhau từ trước (giống chứng chỉ).

Khóa lưu trong thư mục keys/ cạnh file này (KHÔNG đẩy lên repo):
    keys/<name>_private.pem, keys/<name>_public.pem

Chạy riêng:  python dh_auth.py   -> sinh khóa cho alice và bob
"""

import os

# Thư mục keys/ luôn nằm cạnh file này, chạy từ thư mục nào cũng được
KEYS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "keys")


def generate_signing_keys(name: str) -> None:
    """Sinh cặp khóa RSA 2048 bit, lưu vào keys/<name>_private.pem và keys/<name>_public.pem."""
    # TODO(TV4): rsa.generate_private_key(public_exponent=65537, key_size=2048)
    #            os.makedirs(KEYS_DIR, exist_ok=True), ghi 2 file PEM.
    raise NotImplementedError("TV4: generate_signing_keys chưa cài đặt")


def load_private_key(name: str):
    """Đọc khóa riêng RSA từ keys/<name>_private.pem (chưa có file thì báo FileNotFoundError)."""
    # TODO(TV4): serialization.load_pem_private_key(data, password=None)
    raise NotImplementedError("TV4: load_private_key chưa cài đặt")


def load_public_key(name: str):
    """Đọc khóa công khai RSA từ keys/<name>_public.pem (chưa có file thì báo FileNotFoundError)."""
    # TODO(TV4): serialization.load_pem_public_key(data)
    raise NotImplementedError("TV4: load_public_key chưa cài đặt")


def sign_dh_public(private_key, p: int, g: int, public_value: int) -> bytes:
    """Ký chuỗi f"{p}|{g}|{public_value}" bằng RSA-PSS + SHA-256, trả về chữ ký."""
    # TODO(TV4): padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)
    raise NotImplementedError("TV4: sign_dh_public chưa cài đặt")


def verify_dh_public(public_key, p: int, g: int, public_value: int, signature: bytes) -> bool:
    """Trả về True nếu chữ ký đúng, False nếu sai (bắt InvalidSignature, không để lỗi văng ra)."""
    raise NotImplementedError("TV4: verify_dh_public chưa cài đặt")


if __name__ == "__main__":
    # TODO(TV4): sinh khóa cho "alice" và "bob", ký thử rồi kiểm tra
    #            chữ ký đúng -> True, sửa public_value -> False.
    print("dh_auth.py: chưa có phần tự kiểm thử")
