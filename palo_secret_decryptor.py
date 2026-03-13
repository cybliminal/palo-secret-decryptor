import importlib.metadata
from base64 import b64decode, b64encode
from binascii import hexlify
from hashlib import md5, sha1

import cyclopts
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# The default master key used by Palo Alto Firewalls
DEFAULT_MASTER_KEY = b"p1a2l3o4a5l6t7o8"
APP = "palo-secret-decryptor"

__version__ = importlib.metadata.version(APP)
__author__ = importlib.metadata.metadata(APP)["Author"]


def get_version() -> str:
    return f"{__version__} (maintained by {__author__})"


app = cyclopts.App(name=APP, version=get_version(), help_on_error=True)


# Do all the heavy crypto work here
class PanCrypt:
    def __init__(self, key: bytes = DEFAULT_MASTER_KEY) -> None:
        backend = default_backend()
        key = self._derivekey(key)
        self.c = Cipher(algorithms.AES(key), modes.CBC(b"\0" * 16), backend=backend)

    def _derivekey(self, key: bytes) -> bytes:
        salt = b"\x75\xb8\x49\x83\x90\xbc\x2a\x65\x9c\x56\x93\xe7\xe5\xc5\xf0\x24"  # md5("pannetwork")
        return md5(key + salt).digest() * 2

    def pad(self, d: bytes) -> bytes:
        padder = padding.PKCS7(128).padder()
        return padder.update(d) + padder.finalize()

    def unpad(self, d: bytes) -> bytes:
        unpadder = padding.PKCS7(128).unpadder()
        return unpadder.update(d) + unpadder.finalize()

    def _encrypt(self, data: bytes) -> bytes:
        e = self.c.encryptor()
        return e.update(self.pad(data)) + e.finalize()

    def decrypt(self, data: bytes) -> bytes:
        d = self.c.decryptor()
        # strip off the prefix and sha1 hash
        ct = b64decode(data[33:])
        return self.unpad(d.update(ct) + d.finalize())

    def encrypt(self, data: bytes) -> bytes:
        v = b"AQ=="  # version 1 / adding b converts a string to bytes. Possibly a sexier way but this works
        hash = b64encode(sha1(data).digest())
        ct = b64encode(self._encrypt(data))
        # concatenate version, hash, and secret
        return b"-" + v + hash + ct


@app.default
def palo_secret_decryptor(
    secret: bytes | str, master_key: bytes | str = DEFAULT_MASTER_KEY
) -> None:
    """
    Decrypt a Palo Alto Networks secret using the provided master key.

    Args:
        secret (bytes | str): The encrypted secret string to decrypt. Must start with '-AQ=='.
        master_key (bytes | str, optional): The master key used for decryption. Defaults to the built-in master key.

    Raises:
        SystemExit: If the secret is invalid or the master key is incorrect.

    CLI Usage:
        palo-secret-decryptor SECRET [--master-key MASTER_KEY]

    Example:
        palo-secret-decryptor "-AQ==..." --master-key "mycustomkey"
    """

    # convert supplied keys to byte strings
    if isinstance(secret, str):
        secret = secret.encode("utf-8")
    secret = bytes(secret)
    if isinstance(master_key, str):
        master_key = master_key.encode("utf-8")
    master_key = bytes(master_key)
    crypt = PanCrypt(key=master_key)
    if not secret.startswith(b"-AQ=="):
        raise SystemExit("Error: Invalid secret")
    try:
        print("secret: {}".format(crypt.decrypt(secret).decode("utf-8")))
    except ValueError as _:
        sha1hash = hexlify(b64decode(secret[4:33]))
        print("sha1: {}".format(sha1hash.decode("utf-8")))
        raise SystemExit("Error: Incorrect Master Key")


if __name__ == "__main__":
    app()
