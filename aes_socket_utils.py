import os
import struct
from typing import Tuple

from Crypto.Cipher import AES

BLOCK_SIZE = 16
LENGTH_HEADER_SIZE = 4
KEY_LENGTH_HEADER_SIZE = 4
IV_SIZE = 16
VALID_KEY_SIZES = (16, 32)


def pad(data: bytes) -> bytes:
    """Apply PKCS#7 padding for AES block size."""
    pad_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([pad_len]) * pad_len


def unpad(data: bytes) -> bytes:
    """Remove and validate PKCS#7 padding."""
    if not data:
        raise ValueError("Dữ liệu rỗng, không thể bỏ padding.")

    pad_len = data[-1]
    if pad_len < 1 or pad_len > BLOCK_SIZE:
        raise ValueError("Padding không hợp lệ.")

    expected = bytes([pad_len]) * pad_len
    if data[-pad_len:] != expected:
        raise ValueError("Padding PKCS#7 không hợp lệ.")

    return data[:-pad_len]


def generate_key_iv(key_size: int = 16) -> Tuple[bytes, bytes]:
    """Generate AES key and IV."""
    if key_size not in VALID_KEY_SIZES:
        raise ValueError("AES key size phải là 16 bytes (AES-128) hoặc 32 bytes (AES-256).")
    return os.urandom(key_size), os.urandom(IV_SIZE)


def validate_key_iv(key: bytes, iv: bytes) -> None:
    if len(key) not in VALID_KEY_SIZES:
        raise ValueError("AES key phải dài 16 hoặc 32 byte.")
    if len(iv) != IV_SIZE:
        raise ValueError("IV của AES-CBC phải dài 16 byte.")


def encrypt_aes_cbc(
    plain: bytes,
    key: bytes | None = None,
    iv: bytes | None = None,
    key_size: int = 16,
) -> Tuple[bytes, bytes, bytes]:
    """Encrypt plaintext with AES-CBC and PKCS#7 padding."""
    if key is None or iv is None:
        key, iv = generate_key_iv(key_size)

    validate_key_iv(key, iv)

    cipher = AES.new(key, AES.MODE_CBC, iv)
    cipher_bytes = cipher.encrypt(pad(plain))
    return key, iv, cipher_bytes


def decrypt_aes_cbc(key: bytes, iv: bytes, cipher_bytes: bytes) -> bytes:
    """Decrypt AES-CBC ciphertext and remove PKCS#7 padding."""
    validate_key_iv(key, iv)

    if len(cipher_bytes) == 0:
        raise ValueError("Ciphertext không được rỗng.")
    if len(cipher_bytes) % BLOCK_SIZE != 0:
        raise ValueError("Ciphertext phải có độ dài là bội số của 16 byte.")

    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(cipher_bytes))


def build_key_packet(key: bytes, iv: bytes) -> bytes:
    """Build packet for key channel: key_length + key + iv."""
    validate_key_iv(key, iv)
    return struct.pack("!I", len(key)) + key + iv


def parse_key_packet(packet: bytes) -> Tuple[bytes, bytes]:
    """Parse key channel packet."""
    if len(packet) < KEY_LENGTH_HEADER_SIZE + IV_SIZE:
        raise ValueError("Key packet quá ngắn.")

    key_len = struct.unpack("!I", packet[:KEY_LENGTH_HEADER_SIZE])[0]
    if key_len not in VALID_KEY_SIZES:
        raise ValueError("Key length không hợp lệ.")

    expected_len = KEY_LENGTH_HEADER_SIZE + key_len + IV_SIZE
    if len(packet) != expected_len:
        raise ValueError("Key packet có độ dài không đúng.")

    key_start = KEY_LENGTH_HEADER_SIZE
    key_end = key_start + key_len
    key = packet[key_start:key_end]
    iv = packet[key_end:key_end + IV_SIZE]
    validate_key_iv(key, iv)
    return key, iv


def build_data_packet(cipher_bytes: bytes) -> bytes:
    """Build packet for data channel: ciphertext_length + ciphertext."""
    if len(cipher_bytes) == 0:
        raise ValueError("Ciphertext không được rỗng.")
    return struct.pack("!I", len(cipher_bytes)) + cipher_bytes


def parse_length_header(header: bytes) -> int:
    """Parse 4-byte network-order length header."""
    if len(header) != LENGTH_HEADER_SIZE:
        raise ValueError("Length header phải dài đúng 4 byte.")
    length = struct.unpack("!I", header)[0]
    if length <= 0:
        raise ValueError("Length header phải lớn hơn 0.")
    return length


def recv_exact(conn, n: int) -> bytes:
    """Receive exactly n bytes from a TCP connection."""
    if n <= 0:
        raise ValueError("Số byte cần nhận phải lớn hơn 0.")

    chunks = []
    received = 0
    while received < n:
        chunk = conn.recv(n - received)
        if not chunk:
            raise ConnectionError("Kết nối bị đóng trước khi nhận đủ dữ liệu.")
        chunks.append(chunk)
        received += len(chunk)
    return b"".join(chunks)
def parse_data_packet(packet: bytes) -> bytes:
    """Parse data channel packet: bóc tách ciphertext từ gói tin."""
    if len(packet) < LENGTH_HEADER_SIZE:
        raise ValueError("Data packet quá ngắn, không chứa đủ header.")
    cipher_len = struct.unpack("!I", packet[:LENGTH_HEADER_SIZE])[0]
    ciphertext = packet[LENGTH_HEADER_SIZE : LENGTH_HEADER_SIZE + cipher_len]
    
    if len(ciphertext) != cipher_len:
        raise ValueError("Độ dài Ciphertext nhận được không khớp với header.")
        
    return ciphertext