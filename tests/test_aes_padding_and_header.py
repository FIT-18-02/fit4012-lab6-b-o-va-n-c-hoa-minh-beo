import pytest
from aes_socket_utils import (
    build_data_packet,
    build_key_packet,
    encrypt_aes_cbc,
    decrypt_aes_cbc,
    parse_key_packet,
    parse_length_header,
    pad,
    unpad,
)


def test_pad_unpad_roundtrip():
    data = b"hello AES socket"
    assert unpad(pad(data)) == data


def test_aes_cbc_roundtrip():
    plain = b"FIT4012 Lab 6 AES-CBC"
    key, iv, cipher_bytes = encrypt_aes_cbc(plain, key=b"1" * 16, iv=b"2" * 16)
    assert len(key) == 16
    assert len(iv) == 16
    assert len(cipher_bytes) % 16 == 0


def test_key_packet_roundtrip():
    key = b"1" * 16
    iv = b"2" * 16
    packet = build_key_packet(key, iv)
    parsed_key, parsed_iv = parse_key_packet(packet)
    assert parsed_key == key
    assert parsed_iv == iv


def test_data_packet_contains_correct_length():
    _, _, cipher_bytes = encrypt_aes_cbc(b"FIT4012", key=b"1" * 16, iv=b"2" * 16)
    packet = build_data_packet(cipher_bytes)
    length = parse_length_header(packet[:4])
    assert length == len(cipher_bytes)
    assert packet[4:] == cipher_bytes

def test_ca1_happy_path():
    """Ca 1: plain -> encrypt -> decrypt -> plain"""
    plain = b"FIT4012 Lab 6 AES-CBC"
    # Mã hóa
    key, iv, cipher_bytes = encrypt_aes_cbc(plain)
    # Giải mã ngược lại
    decrypted = decrypt_aes_cbc(key, iv, cipher_bytes)
    # Kết quả phải khớp hoàn toàn với bản gốc
    assert decrypted == plain
def test_ca7_empty_message_logic():
    """
    Ca 7: Kiểm tra xử lý bản tin rỗng
    Mục tiêu: Đảm bảo PKCS#7 vẫn tạo ra 1 khối padding đầy đủ cho chuỗi rỗng
    """
    plaintext = b""
    
    key, iv, ciphertext = encrypt_aes_cbc(plaintext)
    
    assert len(ciphertext) == 16, "Bản tin rỗng phải có ciphertext dài 16 bytes"
    
    decrypted = decrypt_aes_cbc(key, iv, ciphertext)
    assert decrypted == b"", "Giải mã bản tin rỗng phải trả về b''"