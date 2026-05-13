import pytest
from aes_socket_utils import encrypt_aes_cbc, decrypt_aes_cbc


def test_tampered_ciphertext_should_fail_or_change_plaintext():
    plain = b"Thong diep dung de test tamper"
    key = b"1" * 16
    iv = b"2" * 16
    _, _, cipher_bytes = encrypt_aes_cbc(plain, key=key, iv=iv)

    tampered = bytearray(cipher_bytes)
    tampered[-1] ^= 0x01

    try:
        recovered = decrypt_aes_cbc(key, iv, bytes(tampered))
        assert recovered != plain
    except ValueError:
        assert True
def test_ca5_ciphertext_tampering_fails():
    """
    Ca 5: Kiểm tra dữ liệu bị giả mạo (Tamper Detection)
    Mục tiêu: Đảm bảo hệ thống phát hiện được khi ciphertext bị thay đổi
    """
    plaintext = b"Phien giao dich chuyen khoan 100 trieu dong"
    
    key, iv, ciphertext = encrypt_aes_cbc(plaintext)
    
    tampered_ciphertext = bytearray(ciphertext)
    
    for i in range(1, 5):
        tampered_ciphertext[-i] = (tampered_ciphertext[-i] + 1) % 256
    
    tampered_ciphertext = bytes(tampered_ciphertext)
    
    with pytest.raises(ValueError) as excinfo:
        decrypt_aes_cbc(key, iv, tampered_ciphertext)
    
    assert "Padding" in str(excinfo.value)