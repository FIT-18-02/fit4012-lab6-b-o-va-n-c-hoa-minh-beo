import os
import pytest
from aes_socket_utils import encrypt_aes_cbc, decrypt_aes_cbc, generate_key_iv, IV_SIZE

def test_wrong_key_should_not_recover_original_plaintext():
    plain = b"Thong diep dung de test wrong key"
    key = b"1" * 16
    iv = b"2" * 16
    _, _, cipher_bytes = encrypt_aes_cbc(plain, key=key, iv=iv)

    wrong_key = b"3" * 16

    try:
        recovered = decrypt_aes_cbc(wrong_key, iv, cipher_bytes)
        assert recovered != plain
    except ValueError:
        assert True
def test_ca4_wrong_key_decryption_fails():
    """
    Ca 4: Kiểm tra giải mã thất bại khi dùng sai khóa
    Mục tiêu: Đảm bảo hệ thống báo lỗi 'Padding không hợp lệ' khi khóa không khớp
    """
    plaintext = b"Thong tin bi mat can bao ve"
    
    key_correct, iv, ciphertext = encrypt_aes_cbc(plaintext)
    
    key_wrong, _ = generate_key_iv(len(key_correct))
    
    assert key_wrong != key_correct
    
    with pytest.raises(ValueError) as excinfo:
        decrypt_aes_cbc(key_wrong, iv, ciphertext)
    
    assert "Padding" in str(excinfo.value)
def test_ca6_wrong_iv_decryption_fails():
    """
    Ca 6: Kiểm tra sai IV (Dùng dữ liệu ngắn để ép lỗi padding)
    """
    plaintext = b"Short_Data" 
    
    key, iv_correct, ciphertext = encrypt_aes_cbc(plaintext)
    
    iv_wrong = os.urandom(IV_SIZE)
    
    with pytest.raises(ValueError) as excinfo:
        decrypt_aes_cbc(key, iv_wrong, ciphertext)
    
    assert "Padding" in str(excinfo.value)