"""SEC-03 — Demo brute-force khóa HS256 yếu (chứng minh, không phải pytest).

Mục tiêu: minh họa vì sao hệ thống production KHÔNG dùng HS256 cho token public-
facing. Nếu Identity Provider ký HS256 bằng một shared secret yếu (ngắn, nằm trong
từ điển), kẻ tấn công bắt được 1 token là có thể dò ra secret offline rồi tự đúc
token giả mạo tùy ý (arbitrary token forgery) — phá vỡ toàn bộ trust boundary.

Đây chính là lý do (xem docs/crypto-analysis.md & final_report Mục 3) Gateway chọn
ES256 (bất đối xửng) cho client-facing và chỉ giữ HS256 để đối chứng benchmark.

Chạy:
    python -m tests.security.sec03_weak_hs256_demo

Lưu ý: chỉ để dùng trong phòng lab / token tự sinh. Không nhắm vào hệ thống thật.
"""
import sys
import time
import warnings
import itertools
import string

import jwt  # PyJWT

# Console Windows mặc định cp1252 không in được tiếng Việt -> ép UTF-8.
try:
    sys.stdout.reconfigure(encoding="utf-8")
except (AttributeError, ValueError):  # pragma: no cover
    pass

# Token cố tình dùng khóa ngắn để demo -> bỏ qua cảnh báo độ dài khóa của PyJWT.
warnings.filterwarnings("ignore", message=".*HMAC key.*")


def mint_weak_token(secret: str) -> str:
    """Giả lập IdP cấu hình sai: ký HS256 bằng secret yếu."""
    payload = {"sub": "victim", "role": "user", "exp": int(time.time()) + 3600}
    return jwt.encode(payload, secret, algorithm="HS256")


def crack_dictionary(token: str, wordlist: list[str]) -> str | None:
    """Thử từng ứng viên trong wordlist; trả về secret nếu chữ ký khớp."""
    for candidate in wordlist:
        try:
            jwt.decode(token, candidate, algorithms=["HS256"],
                       options={"verify_exp": False})
            return candidate
        except jwt.InvalidSignatureError:
            continue
        except jwt.PyJWTError:
            # exp/aud... sai nhưng chữ ký đúng vẫn coi là crack thành công
            return candidate
    return None


def crack_bruteforce(token: str, charset: str, max_len: int) -> str | None:
    """Vét cạn mọi chuỗi độ dài <= max_len. Chỉ khả thi với secret CỰC ngắn."""
    for length in range(1, max_len + 1):
        for combo in itertools.product(charset, repeat=length):
            candidate = "".join(combo)
            try:
                jwt.decode(token, candidate, algorithms=["HS256"],
                           options={"verify_exp": False})
                return candidate
            except jwt.InvalidSignatureError:
                continue
            except jwt.PyJWTError:
                return candidate
    return None


def main() -> None:
    print("=== SEC-03: HS256 weak-key brute force demo ===\n")

    # Kịch bản 1: secret nằm trong từ điển phổ biến (giống rockyou.txt rút gọn).
    weak_secret = "secret"
    token = mint_weak_token(weak_secret)
    wordlist = ["password", "123456", "admin", "key", "secret", "changeme", "nt219"]
    t0 = time.perf_counter()
    found = crack_dictionary(token, wordlist)
    dt = (time.perf_counter() - t0) * 1000
    print(f"[Dictionary] token ký bằng '{weak_secret}'")
    print(f"  -> cracked = {found!r} trong {dt:.2f} ms "
          f"({wordlist.index(found) + 1 if found else '-'} lần thử)\n")

    # Kịch bản 2: secret 3 ký tự số -> vét cạn keyspace nhỏ.
    short_secret = "739"
    token2 = mint_weak_token(short_secret)
    t0 = time.perf_counter()
    found2 = crack_bruteforce(token2, string.digits, max_len=3)
    dt2 = (time.perf_counter() - t0) * 1000
    print(f"[Brute force] token ký bằng '{short_secret}' (charset=digits, len<=3)")
    print(f"  -> cracked = {found2!r} trong {dt2:.2f} ms\n")

    print("KẾT LUẬN: secret HS256 ngắn/đoán được = forgery toàn hệ thống.")
    print("Khuyến nghị: secret >= 32 bytes ngẫu nhiên, hoặc dùng ES256 + JWKS.")


if __name__ == "__main__":
    main()
