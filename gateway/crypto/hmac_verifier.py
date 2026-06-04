import hmac
import hashlib
import time

# Secret Key dùng chung giữa Gateway và Service Client (M2M)
HMAC_SECRET = "super-secret-service-key"
# Giới hạn thời gian request hợp lệ (5 phút = 300 giây) để chống găm hàng
TIMESTAMP_WINDOW = 300

class HMACInvalid(Exception): ...

def verify_hmac_signature(timestamp: str, nonce: str, signature_to_check: str) -> bool:
    try:
        # 1. Kiểm tra Timestamp xem request có quá cũ hoặc đi trước thời gian không
        request_time = float(timestamp)
        current_time = time.time()
        if abs(current_time - request_time) > TIMESTAMP_WINDOW:
            raise HMACInvalid("Request timestamp expired or invalid")
            
        # 2. Tạo lại thông điệp (Message) theo đúng định dạng format chuẩn
        # Format: timestamp.nonce
        message = f"{timestamp}.{nonce}".encode()
        
        # 3. Tính toán chữ ký hợp lệ bằng HMAC-SHA256
        expected_signature = hmac.new(
            HMAC_SECRET.encode(),
            message,
            hashlib.sha256
        ).hexdigest()
        
        # 4. So sánh chuỗi an toàn chống Timing Attack
        if not hmac.compare_digest(expected_signature, signature_to_check):
            raise HMACInvalid("Signature mismatch")
            
        return True
    except (ValueError, TypeError):
        raise HMACInvalid("Invalid timestamp format")