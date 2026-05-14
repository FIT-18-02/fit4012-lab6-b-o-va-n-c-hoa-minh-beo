import os
import socket
import threading
from pathlib import Path

from aes_socket_utils import decrypt_aes_cbc, parse_data_packet, parse_key_packet

RECEIVER_HOST = os.getenv("RECEIVER_HOST", "127.0.0.1")
DATA_PORT = int(os.getenv("DATA_PORT", "6000"))
KEY_PORT = int(os.getenv("KEY_PORT", "6001"))
OUTPUT_FILE = os.getenv("OUTPUT_FILE", "")
LOG_FILE = os.getenv("RECEIVER_LOG_FILE", "")

received = {
    "key_packet": None,
    "data_packet": None,
}


def receive_packet(port: int, name: str):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        server.bind((RECEIVER_HOST, port))
        server.listen(1)

        if name == "key":
            print("[+] Receiver dang lang nghe kênh khóa", flush=True)
        else:
            print("[+] Receiver dang lang nghe data channel", flush=True)

        conn, _ = server.accept()

        with conn:
            data = b""

            while True:
                chunk = conn.recv(4096)

                if not chunk:
                    break

                data += chunk

        if name == "key":
            received["key_packet"] = data
        else:
            received["data_packet"] = data


def main():
    t1 = threading.Thread(
        target=receive_packet,
        args=(KEY_PORT, "key")
    )

    t2 = threading.Thread(
        target=receive_packet,
        args=(DATA_PORT, "data")
    )

    t1.start()
    t2.start()

    t1.join()
    t2.join()

    key, iv = parse_key_packet(received["key_packet"])
    ciphertext = parse_data_packet(received["data_packet"])

    plaintext = decrypt_aes_cbc(key, iv, ciphertext)

    text = plaintext.decode("utf-8", errors="ignore")

    lines = [
        "[+] Da nhan key/IV.",
        "[+] Da nhan ciphertext.",
        "[+] Giai ma thanh cong.",
        f"[+] Ban tin goc: {text}",
    ]

    for line in lines:
        print(line, flush=True)

    if OUTPUT_FILE:
        Path(OUTPUT_FILE).write_text(
            text,
            encoding="utf-8"
        )

    if LOG_FILE:
        Path(LOG_FILE).parent.mkdir(
            parents=True,
            exist_ok=True
        )

        Path(LOG_FILE).write_text(
            "\n".join(lines) + "\n",
            encoding="utf-8"
        )


if __name__ == "__main__":
    main()