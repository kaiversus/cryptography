FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
# Copy code thành package `gateway` để import path khớp với pytest (from gateway.xxx).
COPY . /app/gateway/
ENV PYTHONPATH=/app
CMD ["uvicorn", "gateway.main:app", "--host", "0.0.0.0", "--port", "8000"]
