import pytest
import struct
from aes_socket_utils import build_data_packet, parse_data_packet
from aes_socket_utils import build_data_packet, parse_length_header


def test_data_channel_contract():
    ciphertext = b"x" * 32
    packet = build_data_packet(ciphertext)

    assert packet[:4] == (32).to_bytes(4, "big")
    assert parse_length_header(packet[:4]) == 32
    assert packet[4:] == ciphertext


def test_empty_ciphertext_should_fail():
    with pytest.raises(ValueError):
        build_data_packet(b"")


def test_bad_length_header_should_fail():
    with pytest.raises(ValueError):
        parse_length_header(b"\x00\x01")

def test_ca3_data_channel_format():
    """
    Ca 3: Data channel đúng format [ciphertext_length][ciphertext]
    Mục tiêu: Kiểm tra cấu trúc gói tin trên kênh dữ liệu
    """
    fake_ciphertext = b"this_is_encrypted_data_123456" # 29 bytes
    packet = build_data_packet(fake_ciphertext)
    cipher_len_header = struct.unpack("!I", packet[:4])[0]
    assert cipher_len_header == 29, f"Ciphertext length header phải là 29, nhận được {cipher_len_header}"
    assert packet[4:] == fake_ciphertext, "Nội dung ciphertext trong packet bị sai"
    assert len(packet) == 33
    parsed_ciphertext = parse_data_packet(packet)
    assert parsed_ciphertext == fake_ciphertext
