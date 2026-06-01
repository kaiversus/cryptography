import secrets
import hashlib
import base64
import urllib.parse
import webbrowser
import httpx

# 1. Tạo Code Verifier (Chuỗi ngẫu nhiên bảo mật cao)
verifier = secrets.token_urlsafe(64)

# 2. Tạo Code Challenge từ Code Verifier bằng SHA-256 mã hóa Base64URL
challenge_hash = hashlib.sha256(verifier.encode()).digest()
challenge = base64.urlsafe_b64encode(challenge_hash).rstrip(b"=").decode()

# 3. Xây dựng URL để người dùng đăng nhập
auth_url = (
    "http://localhost:8081/realms/nt219/protocol/openid-connect/auth?"
    + urllib.parse.urlencode({
        "client_id": "web-app",
        "response_type": "code",
        "redirect_uri": "http://localhost:3000/callback",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "scope": "openid",
    })
)

print("="*60)
print("VUI LÒNG COPY URL DƯỚI ĐÂY VÀ DÁN VÀO TRÌNH DUYỆT (Nếu trình duyệt không tự mở):")
print(auth_url)
print("="*60)

# Tự động mở trình duyệt
webbrowser.open(auth_url)

# 4. Chờ lập trình viên đăng nhập xong và paste code vào đây
print("\nSau khi đăng nhập thành công, bạn sẽ bị redirect sang trang lỗi hoặc trang localhost:3000.")
print("Hãy nhìn lên thanh địa chỉ của trình duyệt, copy giá trị của đoạn '?code=...'")
code = input("Nhập đoạn 'code' bạn vừa copy vào đây: ").strip()

# 5. Đổi Authorization Code lấy Access Token (Gửi kèm Code Verifier để Keycloak đối chứng)
print("\nĐang gửi request đổi code lấy token...")
token_resp = httpx.post(
    "http://localhost:8081/realms/nt219/protocol/openid-connect/token",
    data={
        "grant_type": "authorization_code",
        "client_id": "web-app",
        "code": code,
        "redirect_uri": "http://localhost:3000/callback",
        "code_verifier": verifier,
    },
    timeout=30.0
)

print("\n[KẾT QUẢ TRẢ VỀ TỪ KEYCLOAK]:")
if token_resp.status_code == 200:
    tokens = token_resp.json()
    print("✓ Lấy Token thành công!")
    print("\n[FULL ACCESS TOKEN DƯỚI ĐÂY - HÃY COPY HẾT]:")
    print(tokens['access_token']) # Xóa bỏ đoạn [:50] đi để nó in ra hết sạch
    print("\n👉 Hãy copy full Access Token này dán vào trang https://jwt.io để kiểm tra.")
    print("👉 Đảm bảo trong phần Header hiển thị: \"alg\": \"ES256\"")
else:
    print(f"❌ Thất bại! Mã lỗi: {token_resp.status_code}")
    print(token_resp.text)