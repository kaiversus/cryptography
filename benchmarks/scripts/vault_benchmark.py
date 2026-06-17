import time
import csv
import os
from gateway.storage.vault_client import get_secret, _cache

# Đảm bảo set biến môi trường trước khi chạy
# export VAULT_ADDR=http://localhost:8200
# export VAULT_TOKEN=dev-root-token

ITERATIONS = 1000
SECRET_PATH = "gateway/hmac/prod-key-01"

def run_benchmark():
    results = []

    # Kịch bản 1: CÓ CACHE (Bật tính năng Cache của ứng dụng)
    print("Đang test kịch bản: CÓ CACHE...")
    _cache.clear() # Xóa cache cũ
    start_time_cache = time.perf_counter()
    for _ in range(ITERATIONS):
        get_secret(SECRET_PATH)
    end_time_cache = time.perf_counter()
    time_with_cache = (end_time_cache - start_time_cache) / ITERATIONS * 1000 # Đổi ra ms

    # Kịch bản 2: KHÔNG CACHE (Ép xóa cache liên tục để mô phỏng)
    print("Đang test kịch bản: KHÔNG CACHE (Gọi trực tiếp Vault 1000 lần)...")
    _cache.clear()
    start_time_nocache = time.perf_counter()
    for _ in range(ITERATIONS):
        get_secret(SECRET_PATH)
        _cache.clear() # Xóa ngay lập tức để vòng sau phải gọi lại HTTP
    end_time_nocache = time.perf_counter()
    time_without_cache = (end_time_nocache - start_time_nocache) / ITERATIONS * 1000 # Đổi ra ms

    # Lưu kết quả ra CSV
    os.makedirs("benchmarks/results", exist_ok=True)
    csv_file = "benchmarks/results/vault_overhead.csv"
    
    with open(csv_file, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["Scenario", "Average_Latency_ms", "Total_Requests"])
        writer.writerow(["Cache_ON", round(time_with_cache, 4), ITERATIONS])
        writer.writerow(["Cache_OFF", round(time_without_cache, 4), ITERATIONS])

    print(f"\n[HOÀN THÀNH] Kết quả đã lưu tại: {csv_file}")
    print(f"- Có Cache: {round(time_with_cache, 4)} ms/request")
    print(f"- Không Cache: {round(time_without_cache, 4)} ms/request")

if __name__ == "__main__":
    run_benchmark()
