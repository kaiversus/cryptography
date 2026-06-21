# DEPLOYMENT & OPERATION RUNBOOK (V1.0.0)

Tài liệu này hướng dẫn chi tiết quy trình triển khai, vận hành và xử lý sự cố cho hệ thống **Secure API Gateway with Cryptographic Enforcement** trên cả hai môi trường: Docker Compose (Phát triển) và Kubernetes (Giả lập Production).

---

## 1. YÊU CẦU MÔI TRƯỜNG (PREREQUISITES)

Trước khi bắt đầu, đảm bảo máy trạm (hoặc máy chủ local) đã cài đặt đầy đủ các công cụ sau:
- **Hệ điều hành:** Linux (Khuyến nghị Ubuntu 22.04 LTS trở lên) hoặc WSL2 trên Windows.
- **Docker & Docker Compose:** Docker Engine v24.0+ / Compose v2.20+.
- **Kubernetes Client:** `kubectl` kết hợp với cụm `minikube`.
- **Python:** Phiên bản 3.11+ kèm theo môi trường ảo `venv`.

---

## 2. TRIỂN KHAI TRÊN MÔI TRƯỜNG DOCKER COMPOSE

Môi trường này điều khiển toàn bộ hạ tầng lõi bao gồm: API Gateway, HashiCorp Vault, Keycloak, Prometheus và Redis qua mạng nội bộ `gw-net`.

### Các bước khởi động hệ thống
1. Di chuyển vào thư mục hạ tầng:
   ```bash
   cd ~/secure-api-gateway/infra


2.  Khởi chạy toàn bộ cụm container ở chế độ chạy ngầm:
    docker compose up -d

3.  Kiểm tra trạng thái sức khỏe (Healthcheck) của các dịch vụ:
    docker compose ps

    Yêu cầu: Toàn bộ dịch vụ ở trạng thái Up hoặc healthy.

Quy trình nạp dữ liệu mẫu (Seed Data)
Hệ thống sử dụng một container phụ trợ mang tên vault-seed để tự động đẩy các khóa HMAC (như prod-key-01) vào Vault ngay khi khởi động. Không cần thao tác thủ công.


## 3. TRIỂN KHAI TRÊN MÔI TRƯỜNG KUBERNETES (MINIKUBE)

Môi trường giả lập production sử dụng kiến trúc Multi-Pod để tăng khả năng chịu tải và tự phục hồi.
Các bước triển khai:

    Khởi động cụm Minikube cục bộ:
    Bash

    minikube start

    Áp dụng các file cấu hình Manifest (Deployment & Service):
    Bash

    cd ~/secure-api-gateway/k8s
    kubectl apply -f deployment.yaml
    kubectl apply -f service.yaml

    Kiểm tra trạng thái phân phối các Pod:
    Bash

    kubectl get pods -l app=api-gateway

    Mở đường ống kết nối (Port-Forwarding) để test API từ máy thật (Localhost):
    Bash

    kubectl port-forward service/gateway 8000:8000

## 4. KỊCH BẢN XỬ LÝ SỰ CỐ (TROUBLESHOOTING RUNBOOK)
# Sự cố 1: Lỗi Error response from daemon: container ... is not running khi chạy lệnh exec

    Triệu chứng: Khi chạy script test hoặc benchmark, Docker báo container Gateway đã chết.

    Nguyên nhân: Thường do lỗi cấu hình mount volume hoặc một dịch vụ phụ thuộc (như Prometheus/Vault) bị crash kéo theo Gateway sập.

    Cách xử lý:

        Kiểm tra log của container bị sập để tìm nguyên nhân:
        Bash

        docker compose logs infra-gateway-1

        Nếu do lỗi cấu hình Prometheus mount nhầm folder, chạy lệnh sửa sai:
        Bash

        rm -rf prometheus.yml && touch prometheus.yml

        Khởi động lại cụm bằng lệnh ép buộc dọn dẹp:
        Bash

        docker compose down && docker compose up -d

# Sự cố 2: Lỗi ModuleNotFoundError: No module named 'gateway' khi chạy test cục bộ

    Triệu chứng: Chạy script Python ngoài máy thật báo không tìm thấy module hệ thống.

    Nguyên nhân: Python không định vị được đường dẫn thư mục gốc dự án trong biến môi trường PYTHONPATH.

    Cách xử lý:

        Cách 1: Thêm cờ khai báo trực tiếp trước lệnh chạy:
        Bash

        PYTHONPATH=. python3 benchmarks/scripts/vault_benchmark.py

        Cách 2 (Khuyến nghị): Sử dụng "Chiến thuật Ninja" chạy trực tiếp trong container đã cấu hình sẵn biến môi trường:
        Bash

        docker exec -e PYTHONPATH=/app -it infra-gateway-1 python /app/vault_benchmark_temp.py

# Sự cố 3: Không thể kết nối từ máy thật vào cụm K8s nội bộ

    Triệu chứng: Gọi curl http://localhost:8000 báo lỗi Connection refused.

    Nguyên nhân: Dải mạng của các Pod trong K8s (10.244.x.x) bị cô lập hoàn toàn với máy thật.

    Cách xử lý: Đục ống định tuyến bằng lệnh forward service trước khi test:
    Bash

    kubectl port-forward service/gateway 8000:8000

## 5. QUY TRÌNH KIỂM TRA HỆ THỐNG (HEALTH CHECK & BENCHMARK)

Để đảm bảo hệ thống vận hành đúng cam kết hiệu năng sau khi deploy, chạy quy trình đo đạc tự động:
Bash

cd ~/secure-api-gateway
docker cp benchmarks/scripts/vault_benchmark.py infra-gateway-1:/app/vault_benchmark_temp.py
docker exec -e PYTHONPATH=/app -e VAULT_ADDR=http://vault:8200 -e VAULT_TOKEN=dev-root-token -it infra-gateway-1 python /app/vault_benchmark_temp.py

Tiêu chuẩn nghiệm thu: Tốc độ kịch bản Cache_ON phải đạt dưới < 0.1 ms/request.
