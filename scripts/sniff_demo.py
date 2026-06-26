#!/usr/bin/env python3
"""sniff_demo.py - KE NGHE LEN ngoi giua client va server (chung minh KB4).

Relay TCP: nghe <listen_port>, chuyen tiep toi <target_host:target_port>, va IN RA
moi dong header nhay cam (Authorization / X-Signature...) bat duoc tu chieu client->server.

  HTTP  : sniffer doc duoc token nguyen van  -> token LO.
  HTTPS : sniffer chi thay ciphertext        -> token AN TOAN.

Dung (PowerShell hoac bash):
  # A) Nghe len kenh HTTP (gateway 18000):
  python scripts/sniff_demo.py 9000 localhost 18000
  #    roi gui:  curl http://localhost:9000/api/protected -H "Authorization: Bearer <TOKEN>"
  #    -> sniffer in ra dong Authorization (token lo).

  # B) Nghe len kenh HTTPS (Caddy edge 9443):
  python scripts/sniff_demo.py 9001 localhost 9443
  #    roi gui:  curl -k https://localhost:9001/api/protected -H "Authorization: Bearer <TOKEN>"
  #    -> sniffer KHONG doc duoc gi (chi byte TLS) -> kenh da ma hoa.
"""
import socket
import sys
import threading

SENSITIVE = (b"authorization:", b"x-signature:", b"x-key-id:", b"x-vault-token:")


def pump(src, dst, sniff):
    try:
        while True:
            data = src.recv(4096)
            if not data:
                break
            if sniff:
                for line in data.split(b"\r\n"):
                    low = line.lower()
                    if any(low.startswith(h) for h in SENSITIVE):
                        try:
                            print(f"  [NGHE LEN DUOC] {line.decode('latin-1')}", flush=True)
                        except Exception:
                            pass
            dst.sendall(data)
    except OSError:
        pass
    finally:
        try: dst.shutdown(socket.SHUT_WR)
        except OSError: pass


def handle(client, target):
    try:
        upstream = socket.create_connection(target)
    except OSError as e:
        print(f"  [loi] khong noi duoc toi {target}: {e}", flush=True)
        client.close(); return
    threading.Thread(target=pump, args=(client, upstream, True), daemon=True).start()
    threading.Thread(target=pump, args=(upstream, client, False), daemon=True).start()


def main():
    if len(sys.argv) != 4:
        print("dung: python sniff_demo.py <listen_port> <target_host> <target_port>")
        sys.exit(1)
    lport = int(sys.argv[1]); target = (sys.argv[2], int(sys.argv[3]))
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", lport)); srv.listen()
    print(f"[sniffer] nghe 127.0.0.1:{lport} -> chuyen tiep {target[0]}:{target[1]}", flush=True)
    print("[sniffer] dang cho request... (Ctrl+C de dung)", flush=True)
    while True:
        c, _ = srv.accept()
        threading.Thread(target=handle, args=(c, target), daemon=True).start()


if __name__ == "__main__":
    main()
