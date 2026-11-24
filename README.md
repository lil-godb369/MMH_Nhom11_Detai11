# MMH – Nhóm 11 – Đề tài 11: Diffie-Hellman và tấn công MITM

Cài đặt giao thức trao đổi khóa Diffie-Hellman giữa hai bên trên kênh truyền công khai, mô phỏng tấn công người đứng giữa (MITM) khi không có xác thực, và chặn MITM bằng chữ ký số.

## 1. Thành viên

| Thành viên | Họ tên | File phụ trách |
| --- | --- | --- |
| TV1 – Trưởng nhóm |Trần Ngọc Đăng Khoa | `dh_math.py`, `dh_protocol.py`, `main.py` |
| TV2 |Lê Thị Minh Chiến | `channel.py`, `alice.py`, `bob.py` |
| TV3 |Nguyễn Cao Nguyên | `mallory.py` |
| TV4 |Trần Ngọc Tài | `dh_auth.py`, `benchmark.py` |

## 2. Ngôn ngữ và thư viện

- **Python 3.10 trở lên.**
- Thư viện có sẵn của Python: `socket`, `json`, `hashlib`, `secrets`, `threading`, `argparse`, `time`.
- Thư viện cài thêm: `cryptography`, chỉ dùng cho mã hóa AES-GCM và chữ ký RSA. Cài bằng lệnh `pip install -r requirements.txt`.
- **Phần Diffie-Hellman nhóm tự viết**, không dùng module DH có sẵn của thư viện, vì đây là yêu cầu chính của đề.
- Số ngẫu nhiên dùng `secrets`, không dùng `random`, vì `random` đoán trước được nên không an toàn cho mật mã.

## 3. Cấu trúc thư mục

```
MMH_Nhom11_Detai11/
├── README.md
├── requirements.txt
├── .gitignore
├── dh_math.py        TV1  Hàm toán học: lũy thừa modulo, Miller–Rabin, sinh p, tìm g
├── dh_protocol.py    TV1  Sinh khóa, tính khóa chung, tạo khóa AES, mã hóa tin nhắn
├── main.py           TV1  Chạy 4 kịch bản: normal, mitm, auth, auth-alice
├── channel.py        TV2  Gửi/nhận tin nhắn qua socket, in ra những gì kẻ nghe lén thấy
├── alice.py          TV2  Bên Alice (client)
├── bob.py            TV2  Bên Bob (server)
├── mallory.py        TV3  Kẻ tấn công đứng giữa
├── dh_auth.py        TV4  Chữ ký RSA để xác thực khóa công khai DH
├── benchmark.py      TV4  Đo thời gian theo độ dài p
├── keys/                  Khóa RSA do dh_auth.py sinh ra (KHÔNG đẩy lên repo)
└── docs/
    ├── bao_cao/           Chương báo cáo của từng người
    ├── slide/
    └── hinh_anh/          Ảnh chụp log, lưu đồ
```

## 4. Luồng chạy

- Bob mở cổng **5000** và chờ kết nối.
- **Bình thường:** Alice kết nối thẳng tới Bob (cổng 5000).
- **Bị MITM:** Alice kết nối tới Mallory (cổng **5001**), Mallory kết nối tiếp tới Bob. Alice tưởng mình đang nói chuyện với Bob.

Mỗi tin nhắn là **một dòng JSON**, kết thúc bằng ký tự xuống dòng:

| Bước | Chiều | Nội dung |
| --- | --- | --- |
| 1 | Alice → Bob | `{"type": "dh_init", "p": ..., "g": ..., "public": A}` |
| 2 | Bob → Alice | `{"type": "dh_reply", "public": B}` |
| 3 | Alice → Bob | `{"type": "data", "nonce": "<hex>", "ciphertext": "<hex>"}` |
| 4 | Bob → Alice | `{"type": "data", ...}` – tin trả lời |
| – | Bên bất kỳ | `{"type": "error", "reason": "..."}` khi kiểm tra thất bại |

Ở chế độ có xác thực (`auth=True`), tin nhắn bước 1 và 2 có thêm trường `"signature": "<hex>"`. Giả định Alice và Bob đã có sẵn khóa công khai RSA của nhau từ trước, giống như chứng chỉ.

**Kết quả mong đợi của 4 kịch bản:**

| Kịch bản | Kết quả |
| --- | --- |
| `normal` | Alice và Bob tính ra cùng một khóa, Bob đọc đúng tin nhắn |
| `mitm` | Mallory đọc được tin nhắn và sửa nội dung (vd: 100.000đ → 900.000đ); Bob nhận tin đã bị sửa mà không biết |
| `auth` | Mallory vẫn chen vào giữa nhưng không làm giả được chữ ký; Bob báo "Phát hiện MITM" và ngắt kết nối |
| `auth-alice` | Mallory chuyển nguyên `dh_init`, chỉ thay khóa trong `dh_reply` của Bob; Bob chấp nhận Alice, còn Alice thấy chữ ký Bob sai, báo "Phát hiện MITM", gửi `error` cho bên kia rồi hủy phiên |

Thêm cờ `--forge` (với `mitm`, `auth`, `auth-alice`): Mallory tự ký khóa giả bằng khóa RSA `mallory` của mình (sinh nếu chưa có) thay vì giữ chữ ký cũ. Kết quả vẫn như trên vì Alice/Bob xác minh bằng khóa công khai của nhau, không phải của Mallory.

Bên nhận `dh_init` (Bob, Mallory) kiểm tra tham số bằng `is_valid_params`: p phải là số nguyên tố an toàn dài ít nhất 512 bit nên `--bits` nhỏ hơn 512 sẽ bị Bob từ chối.

## 5. Tên hàm dùng chung

### `dh_math.py` – TV1

| Hàm | Trả về | Việc làm |
| --- | --- | --- |
| `mod_pow(base, exp, mod)` | `int` | Tính base^exp mod mod bằng bình phương và nhân |
| `is_probable_prime(n, rounds=40)` | `bool` | Kiểm tra số nguyên tố bằng Miller–Rabin |
| `generate_safe_prime(bits)` | `int` | Sinh p = 2q + 1 với p, q đều nguyên tố, p dài `bits` bit |
| `find_generator(p)` | `int` | Tìm g sao cho g² mod p ≠ 1 và g^q mod p ≠ 1 |
| `get_params(bits)` | `(p, g)` | 1024 bit: dùng RFC 2409 nhóm 2; 2048 bit: dùng RFC 3526 nhóm 14; độ dài khác: tự sinh |

### `dh_protocol.py` – TV1

| Hàm | Trả về | Việc làm |
| --- | --- | --- |
| `generate_private_key(p)` | `int` | Số ngẫu nhiên trong đoạn [2, p − 2] |
| `compute_public_key(g, private_key, p)` | `int` | Tính g^a mod p |
| `compute_shared_secret(other_public, private_key, p)` | `int` | Tính B^a mod p |
| `is_valid_public_key(value, p)` | `bool` | Kiểm tra 2 ≤ value ≤ p − 2, chặn khóa công khai bất thường |
| `is_valid_params(p, g, min_bits=512)` | `bool` | p, g là `int` (không phải `bool`), p ≥ `min_bits` bit, p và (p − 1)/2 đều nguyên tố (nhóm RFC có sẵn thì bỏ qua Miller–Rabin), 2 ≤ g ≤ p − 2, g² mod p ≠ 1 |
| `derive_aes_key(shared_secret, p)` | `bytes` (32 byte) | Đổi khóa chung sang bytes dài cố định bằng độ dài byte của p (NIST SP 800-56A), băm SHA-256 ra khóa AES-256 |
| `encrypt_message(key, plaintext)` | `(nonce, ciphertext)` | Mã hóa AES-256-GCM, nonce 12 byte ngẫu nhiên |
| `decrypt_message(key, nonce, ciphertext)` | `str` | Giải mã; báo lỗi nếu tin nhắn bị sửa trên đường truyền |

### `channel.py` – TV2

| Tên | Trả về | Việc làm |
| --- | --- | --- |
| `HOST`, `BOB_PORT`, `MALLORY_PORT` | hằng số | `"127.0.0.1"`, `5000`, `5001` |
| `send_msg(sock, msg)` | `None` | Gửi dict dưới dạng một dòng JSON; in ra những gì kẻ nghe lén thấy |
| `recv_msg(reader)` | `dict` | Đọc một dòng JSON. `reader = sock.makefile("r", encoding="utf-8")`, mỗi kết nối chỉ tạo một lần |

### `alice.py`, `bob.py` – TV2

| Hàm | Việc làm |
| --- | --- |
| `run_alice(port=BOB_PORT, auth=False, bits=512, message="...")` | Kết nối, gửi `dh_init`, nhận `dh_reply`, gửi tin nhắn đã mã hóa, nhận tin trả lời. Có xác thực mà chữ ký Bob sai thì gửi `error`, log "Phát hiện MITM" rồi dừng |
| `run_bob(port=BOB_PORT, auth=False)` | Chờ một kết nối, kiểm tra `is_valid_params`, gửi `dh_reply`, giải mã tin nhắn, gửi tin trả lời. Nhận `error` thay cho `data` thì log và dừng |

### `mallory.py` – TV3

| Hàm | Việc làm |
| --- | --- |
| `run_mallory(listen_port=MALLORY_PORT, bob_port=BOB_PORT, mode="both", forge=False)` | Nhận kết nối của Alice, tự kết nối tới Bob, thay khóa công khai bằng khóa của Mallory, đọc và sửa tin nhắn rồi chuyển tiếp. `mode="both"`: thay cả hai chiều; `mode="bob-only"`: chuyển nguyên `dh_init`, chỉ thay khóa trong `dh_reply`. `forge=True`: tự ký khóa giả bằng khóa RSA `mallory` |

### `dh_auth.py` – TV4

| Hàm | Trả về | Việc làm |
| --- | --- | --- |
| `generate_signing_keys(name)` | `None` | Sinh cặp khóa RSA 2048 bit, lưu vào `keys/<name>_private.pem` và `keys/<name>_public.pem` |
| `load_private_key(name)`, `load_public_key(name)` | khóa RSA | Đọc khóa từ thư mục `keys/` |
| `sign_dh_public(private_key, p, g, public_value)` | `bytes` | Ký chuỗi `f"{p}|{g}|{public_value}"` bằng RSA-PSS + SHA-256 |
| `verify_dh_public(public_key, p, g, public_value, signature)` | `bool` | `True` nếu chữ ký đúng |

### `benchmark.py` – TV4

| Hàm | Trả về | Việc làm |
| --- | --- | --- |
| `run_benchmark(bits_list=(512, 1024, 2048), runs=20)` | `list[dict]` | Đo thời gian sinh khóa và tính khóa chung, in bảng kết quả |

## 6. Quy ước chung

- Tên hàm và biến viết kiểu `snake_case`; mỗi hàm có docstring tiếng Việt 1–2 dòng.
- Số lớn giữ kiểu `int`. Dữ liệu `bytes` (nonce, ciphertext, chữ ký) đổi sang chuỗi hex khi gửi qua mạng: `.hex()` và `bytes.fromhex()`.
- Mỗi file có khối `if __name__ == "__main__":` để tự chạy thử phần của mình.
- Trong lúc TV1 chưa viết xong `dh_protocol.py`, các bạn khác tạm dùng `pow(g, a, p)` có sẵn của Python để thử, sau đó đổi sang hàm chung.
- Commit message ghi tên người, ví dụ: `[TV3] Mallory sua duoc tin nhan`.
- Luôn `git pull` trước khi sửa code; chỉ sửa file của mình.
- Thư mục `keys/` chứa khóa riêng, không đẩy lên repo (đã thêm vào `.gitignore`).

## 7. Cách chạy

Trên Windows dùng `py -3.14` thay cho `python` (vd `py -3.14 main.py normal`).

```
pip install -r requirements.txt

python main.py normal             # Trao đổi khóa bình thường
python main.py mitm               # Bị MITM, không có xác thực
python main.py auth               # Bị MITM, có xác thực -> Bob phát hiện
python main.py auth-alice         # Mallory chỉ thay khóa của Bob, có xác thực -> Alice phát hiện
python main.py auth --forge       # Mallory tự ký khóa giả bằng khóa RSA của mình -> vẫn bị phát hiện
python main.py normal --bits 2048 # Đổi độ dài p (mặc định 512, tối thiểu 512)
python benchmark.py               # Đo thời gian
```

Khi demo, có thể chạy mỗi bên trong một cửa sổ riêng để thầy cô thấy rõ log của từng bên:

```
python bob.py [--auth]
python mallory.py [--mode both|bob-only] [--forge]
python alice.py --port 5001 [--auth]
```
