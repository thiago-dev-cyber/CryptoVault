"""
CryptoEngine - AES256-GCM com PBKDF2 para derivação de chave.
Cross-plataform, sem dependência do SO.
"""

# Tamanho dos chunks em Bytes (4MB por padrão)
DEFAULT_CHUNK_SIZE = 4 * 1024 * 1024

SALT_SIZE  = 32 # Bytes
NONCE_SIZE = 12 # Bytes - Padrão CGM
KEY_SIZE   = 32 # Bytes - AES-256
KDF_INTERS = 600_000 # OWASP 2024 recomenda > 600k para PBKDF2-SHA256

import os
import hmac
import hashlib
from dataclasses import dataclass, fields
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


@dataclass(frozen=True)
class EncryptedChunk:
    chunk_id: str      # SHA-256 do conteúdo ORIGINAL (para de duplicação).
    chiphertext: bytes # salt(32) + nonce(15) + tag+chiphertext(N+16)
    size_original: int # tamanho antes da cifra (para progress/stat)


class CryptoEngine:
    """
        Responsável por toda operação criptográfica do vault.

        Fluxo da cifra:
            senha + salt -> PBKDF2 -> chave AES-256
            chave + nonce -> AES-256-GCM -> ciphertext + tag (autenticado)

        O salt e nonce são unicos por chunk, gerados via os.urandom().
        O chunk_id é o SHA-256 do conteudo PLAINTEXT - permite deduplicação
        sem export o conteudo (o ID em si não revela nada de útil sem a chave).
    """


    def __init__(self, password: str, chunk_size: int = DEFAULT_CHUNK_SIZE):
        if not password:
            raise ValueError("Senha não pode ser vazia.")
        self._password = password.encode("utf-8")
        self.chunk_size = chunk_size


    def _derive_key(self, salt: bytes):
        """Deriva uma chave AES-256 a partir da senha e salt via PBKDF2-SHA256."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=KEY_SIZE,
            salt=salt,
            iterations=KDF_INTERS,
        )
        return kdf.derive(self._password)
    

    def encrypt_chunk(self, plaintext: bytes) -> EncryptedChunk:
        """
        Cifra um bloco de bytes.

        Layout do chipertext armazenado:
            [salt: 32 bytes][nonce: 16 bytes][GCM chipertext+tag: N+16 bytes]
        """
        chunk_id   = self._content_hash(plaintext)
        salt       = os.urandom(SALT_SIZE)
        nonce      = os.urandom(NONCE_SIZE)
        key        = self._derive_key(salt)
        aesgcm     = AESGCM(key)
        chipertext = aesgcm.encrypt(nonce, plaintext, None)

        blob = salt + nonce + chipertext

        return EncryptedChunk(
            chunk_id=chunk_id,
            chiphertext=blob,
            size_original=len(plaintext)
        )
    
    def decrypt_chunk(self, blob: bytes) -> bytes:
        "Decifra um bloco encriptado pelo encrypt_chunk"
        if len(blob) < SALT_SIZE + NONCE_SIZE + 16:
            raise ValueError("Blob corrompido ou truncado.")

        salt        = blob[:SALT_SIZE]
        nonce       = blob[SALT_SIZE : SALT_SIZE + NONCE_SIZE]
        chiphertext = blob[SALT_SIZE + NONCE_SIZE : ]
        key         = self._derive_key(salt)
        aesgcm      = AESGCM(key)

        try:
            return aesgcm.decrypt(nonce, chiphertext, None)
        except Exception:
            raise ValueError(
                "Falha na decriptação - Senha incorreta ou dado corrompido."
            )


    @staticmethod
    def _content_hash(data: bytes) -> str:
        """SHA-256 do conteudo - usado como chunk_id para deduplicação."""
        return hashlib.sha256(data).hexdigest()


    def file_hash(filepath: str) -> str:
        """SHA-256  de um arquivo inteiro, usado para verificar a integridade."""
        h = hashlib.sha256()
        with open(filepath, "rb") as fh:
            for block in iter(lambda: fh.read(65536), b""):
                h.update(block)
        return h.hexdigest()


    def verify_password(self, test_password: str, salt: bytes, know_hash: str) -> bool:
        """Verifica a senha sem export a chave (timing-safe)"""
        engine = CryptoEngine(test_password, self.chunk_size)
        derive = engine._derive_key(salt)
        return hmac.compare_digest(
            hashlib.sha256(derive).hexdigest(),
            know_hash,
        )