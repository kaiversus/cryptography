import hmac
import hashlib
import time
import uuid
import requests

URL = "http://localhost:8000/api/service"
SECRET = "super-secret-service-key"

# 1. Tạo các tham số bảo mật hợp lệ cho lần đầu tiên
timestamp = str(time.time())
nonce = str(uuid.uuid4())  # Sinh chuỗi ngẫu nhiên dùng 1 lần
message = f"{timestamp}.{nonce}".encode()

# 2. Tính toán chữ ký HMAC-SHA256 xịn
signature = hmac.new(SECRET.encode(), message, hashlib.sha256).hexdigest()

headers = {
    "X-Timestamp": timestamp,
    "X-Nonce": nonce,
    "X-Signature": signature
}

print("=========================================================")
print("🚀 PHA 1: GỬI REQUEST HỢP LỆ (LẦN ĐẦU TIÊN)")
print("=========================================================")
print(f"Headers gửi đi:\n -> X-Timestamp: {timestamp}\n -> X-Nonce: {nonce}\n -> X-Signature: {signature}\n")

try:
    r1 = requests.get(URL, headers=headers)
    print(f"👉 Kết quả từ Gateway: HTTP Status {r1.status_code}")
    print(f"👉 Dữ liệu trả về: {r1.text}\n")
except Exception as e:
    print(f"Lỗi kết nối: {e}")

print("=========================================================")
print("💀 PHA 2: MÔ PHỎNG REPLAY ATTACK (GỬI LẠI Y HỆT GÓI TIN TRÊN)")
print("=========================================================")
time.sleep(1) # Nghỉ 1 giây rồi cố tình gửi lại chuỗi nonce cũ

try:
    r2 = requests.get(URL, headers=headers)
    print(f"👉 Kết quả từ Gateway: HTTP Status {r2.status_code}")
    print(f"👉 Dữ liệu trả về: {r2.text}\n")
except Exception as e:
    print(f"Lỗi kết nối: {e}")
