import os
import tempfile
import unittest

from cryptovault.crypto_engine import CryptoEngine

# -------------------------------------------------------------------------
# Helpers
# -------------------------------------------------------------------------
def make_temp_file(content: bytes, suffix: str = ".bin") -> str:
    fd, path = tempfile.mkstemp(suffix=suffix)
    with os.fdopen(fd, "wb") as f:
        f.write(content)
    return path


# --------------------------------------------------------------------------
# CryptoEngine
# --------------------------------------------------------------------------
class TestCryptoEngine(unittest.TestCase):

    def setUp(self):
        self.engine = CryptoEngine("senha-do-teste-123")

    
    def test_encrypt_decrypt_roundtrip(self):
        plain = b"Hello, Encrypt Vault" * 100
        enc   = self.engine.encrypt_chunk(plain)
        dec   = self.engine.decrypt_chunk(enc.chiphertext)
        self.assertEqual(plain, dec, "Os dados após o decrypt devem ser identicos aos originais.")


    def test_chunk_id_is_content_hash(self):
        plain = b"Conteudo Fixo"
        enc1  = self.engine.encrypt_chunk(plain)
        enc2  = self.engine.encrypt_chunk(plain)
        self.assertEqual(enc1.chunk_id, enc2.chunk_id, "IDs devem ser iguais (hash do plaintext)")
        self.assertNotEqual(enc1.chiphertext, enc2.chiphertext, "Chiphertext devem ser diferentes (nonce aleatorio)")


    def test_wrong_password_raid(self):
        plain = b"Segredo"
        enc   = self.engine.encrypt_chunk(plain)
        bad   = CryptoEngine(password="senha-errada")
        with self.assertRaises(ValueError):
            bad.decrypt_chunk(enc.chiphertext)

    
    def test_tampered_ciphertext_raises(self):
        plain  = b"integridade importa"
        enc    = self.engine.encrypt_chunk(plain)
        tamper = bytearray(enc.chiphertext)
        tamper[50] ^= 0xFF # flip um bit
        with self.assertRaises(ValueError):
            self.engine.decrypt_chunk(bytes(tamper))

    
    def test_file_hash_stability(self):
        content = b"conteudo estavel"
        path    = make_temp_file(content)
        h1      = CryptoEngine.file_hash(path)
        h2      = CryptoEngine.file_hash(path)
        self.assertEqual(h1, h2, "Os hashs devem ser iguais, para arquivos com o mesmo conteudo.")
        os.unlink(path)