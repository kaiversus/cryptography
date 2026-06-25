"""SEC-12 (D1-IG / MT-AVAIL): chống DoS tầng ứng dụng bằng rate-limit.

Vector: hacker bắn hàng loạt request cùng lúc → user thật không vào được.
Phòng thủ: gateway giới hạn số request/IP. /api/public cho tối đa 10/phút;
request thứ 11 trở đi bị chặn 429 → user thật vẫn được phục vụ trong hạn mức.
"""


def test_sec12_rate_limit_blocks_flood(client):
    statuses = [client.get("/api/public").status_code for _ in range(12)]

    # 10 request đầu trong hạn mức → đi qua
    assert all(s == 200 for s in statuses[:10]), statuses
    # vượt ngưỡng → bị chặn 429 (Too Many Requests)
    assert all(s == 429 for s in statuses[10:]), statuses
