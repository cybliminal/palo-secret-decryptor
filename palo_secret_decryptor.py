from hashlib import md5, sha1
from begin import formatters, start
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from base64 import b64encode, b64decode

# The default master key used by Palo Alto Firewalls
DEFAULT_MASTERKEY = b"p1a2l3o4a5l6t7o8"
FORMATTER = formatters.compose(formatters.RawDescription, formatters.RawArguments)


# Do all the heavy crypto work here
class PanCrypt:
    def __init__(self, key=DEFAULT_MASTERKEY):
        backend = default_backend()
        key = self._derivekey(key)
        self.c = Cipher(algorithms.AES(key), modes.CBC(b"\0" * 16), backend=backend)

    def _derivekey(self, key):
        salt = b"\x75\xb8\x49\x83\x90\xbc\x2a\x65\x9c\x56\x93\xe7\xe5\xc5\xf0\x24"  # md5("pannetwork")
        return md5(key + salt).digest() * 2

    def pad(self, d):
        padder = padding.PKCS7(128).padder()
        return padder.update(d) + padder.finalize()

    def unpad(self, d):
        unpadder = padding.PKCS7(128).unpadder()
        return unpadder.update(d) + unpadder.finalize()

    def _encrypt(self, data):
        e = self.c.encryptor()
        return e.update(self.pad(data)) + e.finalize()

    def decrypt(self, data):
        d = self.c.decryptor()
        # strip off the prefix and sha1 hash
        ct = b64decode(data[33:])
        return self.unpad(d.update(ct) + d.finalize())

    def encrypt(self, data):
        v = b"AQ=="  # version 1 / adding b converts a string to bytes. Possibly a sexier way but this works
        hash = b64encode(sha1(data).digest())
        ct = b64encode(self._encrypt(data))
        # concatenate version, hash, and secret
        return b"-" + v + hash + ct


@start(formatter_class=FORMATTER)  # pyright: ignore [reportCallIssue]
def palo_secret_decryptor(secret, master_key=DEFAULT_MASTERKEY):
    # covert supplied keys to byte strings
    if not isinstance(secret, bytes):
        secret = bytes(secret, "utf-8")
    if not isinstance(master_key, bytes):
        master_key = bytes(master_key, "utf-8")
    crypt = PanCrypt(key=master_key)
    if not secret.startswith(b"-AQ=="):
        raise SystemExit("Error: Invalid secret")
    try:
        print(crypt.decrypt(secret).decode("utf-8"))
    except ValueError as _:
        raise SystemExit("Error: Incorrect Master Key")
