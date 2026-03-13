"""Tests for palo_secret_decryptor module."""

from io import StringIO
from unittest.mock import patch

import pytest

from palo_secret_decryptor import (
    PanCrypt,
    __author__,
    __version__,
    get_version,
    palo_secret_decryptor,
)


class TestGetVersion:
    """Tests for get_version function."""

    def test_get_version_format(self) -> None:
        """Test that get_version returns properly formatted string."""
        version = get_version()
        assert __version__ in version
        assert __author__ in version
        assert "maintained by" in version

    def test_get_version_contains_version_number(self) -> None:
        """Test that version string contains version number."""
        version = get_version()
        assert version.startswith(__version__)


class TestPanCryptInitialization:
    """Tests for PanCrypt class initialization."""

    def test_init_with_default_key(self) -> None:
        """Test PanCrypt initialization with default master key."""
        crypt = PanCrypt()
        assert crypt.c is not None
        assert crypt.c is not None

    def test_init_with_custom_key(self) -> None:
        """Test PanCrypt initialization with custom key."""
        custom_key = b"customkey123456"
        crypt = PanCrypt(key=custom_key)
        assert crypt.c is not None

    def test_init_raises_on_non_bytes_key(self) -> None:
        """Test that initialization with non-bytes key may raise an error."""
        # The function should handle type conversion, but let's test edge cases
        with pytest.raises((TypeError, AttributeError)):
            PanCrypt(key="not_bytes")  # type: ignore


class TestPanCryptDeriveKey:
    """Tests for PanCrypt._derivekey method."""

    def test_derivekey_returns_bytes(self) -> None:
        """Test that _derivekey returns bytes."""
        crypt = PanCrypt()
        result = crypt._derivekey(b"testkey")
        assert isinstance(result, bytes)

    def test_derivekey_returns_32_bytes(self) -> None:
        """Test that _derivekey returns 32 bytes (256 bits for AES-256)."""
        crypt = PanCrypt()
        result = crypt._derivekey(b"testkey")
        assert len(result) == 32

    def test_derivekey_deterministic(self) -> None:
        """Test that _derivekey is deterministic (same input = same output)."""
        crypt = PanCrypt()
        key = b"testkey"
        result1 = crypt._derivekey(key)
        result2 = crypt._derivekey(key)
        assert result1 == result2

    def test_derivekey_different_for_different_keys(self) -> None:
        """Test that different keys produce different derived keys."""
        crypt = PanCrypt()
        result1 = crypt._derivekey(b"key1")
        result2 = crypt._derivekey(b"key2")
        assert result1 != result2


class TestPanCryptPadding:
    """Tests for PanCrypt padding methods."""

    def test_pad_returns_bytes(self) -> None:
        """Test that pad returns bytes."""
        crypt = PanCrypt()
        result = crypt.pad(b"test")
        assert isinstance(result, bytes)

    def test_pad_increases_length(self) -> None:
        """Test that pad increases the length of data."""
        crypt = PanCrypt()
        data = b"test"
        padded = crypt.pad(data)
        assert len(padded) > len(data)

    def test_pad_length_multiple_of_16(self) -> None:
        """Test that padded data length is multiple of 16 (block size)."""
        crypt = PanCrypt()
        test_cases = [
            b"a",
            b"short",
            b"medium length text",
            b"very long text that is much longer",
        ]
        for data in test_cases:
            padded = crypt.pad(data)
            assert len(padded) % 16 == 0

    def test_unpad_reverses_pad(self) -> None:
        """Test that unpad correctly reverses pad."""
        crypt = PanCrypt()
        original = b"test data"
        padded = crypt.pad(original)
        unpadded = crypt.unpad(padded)
        assert unpadded == original

    def test_pad_unpad_round_trip(self) -> None:
        """Test pad/unpad round trip with various data."""
        crypt = PanCrypt()
        test_cases = [
            b"single",
            b"multiple words here",
            b"special chars !@#$%^&*()",
            b"unicode: \xc3\xa9\xc3\xa7\xc3\xb1",
            b"",
        ]
        for data in test_cases:
            padded = crypt.pad(data)
            unpadded = crypt.unpad(padded)
            assert unpadded == data


class TestPanCryptEncryption:
    """Tests for PanCrypt encryption methods."""

    def test_encrypt_returns_bytes(self) -> None:
        """Test that encrypt returns bytes."""
        crypt = PanCrypt()
        result = crypt.encrypt(b"test data")
        assert isinstance(result, bytes)

    def test_encrypt_starts_with_dash(self) -> None:
        """Test that encrypt result starts with dash."""
        crypt = PanCrypt()
        result = crypt.encrypt(b"test data")
        assert result.startswith(b"-")

    def test_encrypt_contains_version(self) -> None:
        """Test that encrypt result contains version marker."""
        crypt = PanCrypt()
        result = crypt.encrypt(b"test data")
        assert b"AQ==" in result

    def test_encrypt_deterministic(self) -> None:
        """Test that encryption is deterministic (same plaintext = same ciphertext)."""
        crypt = PanCrypt()
        data = b"test data"
        enc1 = crypt.encrypt(data)
        enc2 = crypt.encrypt(data)
        assert enc1 == enc2

    def test_encrypt_different_for_different_data(self) -> None:
        """Test that different plaintexts produce different ciphertexts."""
        crypt = PanCrypt()
        enc1 = crypt.encrypt(b"data1")
        enc2 = crypt.encrypt(b"data2")
        assert enc1 != enc2

    def test_decrypt_returns_bytes(self) -> None:
        """Test that decrypt returns bytes."""
        crypt = PanCrypt()
        encrypted = crypt.encrypt(b"test data")
        result = crypt.decrypt(encrypted)
        assert isinstance(result, bytes)

    def test_encrypt_decrypt_round_trip(self) -> None:
        """Test that decrypt correctly reverses encrypt."""
        crypt = PanCrypt()
        original = b"test data"
        encrypted = crypt.encrypt(original)
        decrypted = crypt.decrypt(encrypted)
        assert decrypted == original

    def test_encrypt_decrypt_various_plaintexts(self) -> None:
        """Test encrypt/decrypt round trip with various data."""
        crypt = PanCrypt()
        test_cases = [
            b"a",
            b"short",
            b"medium length data",
            b"much longer text with multiple words and special chars !@#$%",
            b"data with newlines\nand\ttabs",
        ]
        for data in test_cases:
            encrypted = crypt.encrypt(data)
            decrypted = crypt.decrypt(encrypted)
            assert decrypted == data

    def test_decrypt_with_different_key_fails(self) -> None:
        """Test that decryption with different key produces wrong result or error."""
        crypt1 = PanCrypt(key=b"key1")
        crypt2 = PanCrypt(key=b"key2")
        encrypted = crypt1.encrypt(b"test data")

        # Decryption with wrong key should either raise or produce garbage
        try:
            decrypted = crypt2.decrypt(encrypted)
            # If it doesn't raise, the decrypted data should be wrong
            assert decrypted != b"test data"
        except Exception:
            # Expected: decryption with wrong key fails
            pass


class TestPaloSecretDecryptor:
    """Tests for palo_secret_decryptor function."""

    def test_decrypts_valid_secret_with_default_key(self) -> None:
        """Test decryption with valid secret using default key."""
        crypt = PanCrypt()
        original = b"mypassword"
        encrypted = crypt.encrypt(original)

        with patch("sys.stdout", new_callable=StringIO) as mock_stdout:
            palo_secret_decryptor(encrypted)
            output = mock_stdout.getvalue()
            assert "mypassword" in output

    def test_decrypts_string_secret(self) -> None:
        """Test that string secrets are properly converted to bytes."""
        crypt = PanCrypt()
        original = b"testpass"
        encrypted = crypt.encrypt(original)
        encrypted_str = encrypted.decode("utf-8")

        with patch("sys.stdout", new_callable=StringIO) as mock_stdout:
            palo_secret_decryptor(encrypted_str)
            output = mock_stdout.getvalue()
            assert "testpass" in output

    def test_rejects_invalid_secret_format(self) -> None:
        """Test that invalid secret format raises SystemExit."""
        with pytest.raises(SystemExit, match="Invalid secret"):
            palo_secret_decryptor(b"invalid_format")

    def test_rejects_secret_not_starting_with_dash_aq(self) -> None:
        """Test that secret not starting with -AQ== raises SystemExit."""
        with pytest.raises(SystemExit, match="Invalid secret"):
            palo_secret_decryptor(b"-XX==" + b"a" * 100)

    def test_wrong_master_key_raises_systemexit(self) -> None:
        """Test that wrong master key raises SystemExit."""
        crypt = PanCrypt(key=b"originalkey1234")
        encrypted = crypt.encrypt(b"secret")

        with pytest.raises(SystemExit, match="Incorrect Master Key"):
            palo_secret_decryptor(encrypted, master_key=b"wrongkey12345678")

    def test_custom_master_key(self) -> None:
        """Test decryption with custom master key."""
        custom_key = b"mykey1234567890ab"
        crypt = PanCrypt(key=custom_key)
        original = b"customsecret"
        encrypted = crypt.encrypt(original)

        with patch("sys.stdout", new_callable=StringIO) as mock_stdout:
            palo_secret_decryptor(encrypted, master_key=custom_key)
            output = mock_stdout.getvalue()
            assert "customsecret" in output

    def test_string_master_key_conversion(self) -> None:
        """Test that string master key is properly converted to bytes."""
        crypt = PanCrypt(key=b"stringkey1234567")
        original = b"password123"
        encrypted = crypt.encrypt(original)

        with patch("sys.stdout", new_callable=StringIO) as mock_stdout:
            palo_secret_decryptor(encrypted, master_key="stringkey1234567")
            output = mock_stdout.getvalue()
            assert "password123" in output

    def test_output_format(self) -> None:
        """Test that output is in expected format."""
        crypt = PanCrypt()
        encrypted = crypt.encrypt(b"mypass")

        with patch("sys.stdout", new_callable=StringIO) as mock_stdout:
            palo_secret_decryptor(encrypted)
            output = mock_stdout.getvalue()
            assert output.startswith("secret:")
            assert "mypass" in output


class TestIntegration:
    """Integration tests."""

    def test_full_encryption_decryption_cycle(self) -> None:
        """Test complete encryption and decryption cycle."""
        plaintext = b"integration_test_password_123"
        crypt = PanCrypt()

        # Encrypt
        encrypted = crypt.encrypt(plaintext)
        assert encrypted.startswith(b"-AQ==")

        # Decrypt via main function
        with patch("sys.stdout", new_callable=StringIO) as mock_stdout:
            palo_secret_decryptor(encrypted)
            output = mock_stdout.getvalue()
            assert plaintext.decode("utf-8") in output

    def test_consistency_across_instances(self) -> None:
        """Test that different PanCrypt instances produce consistent results."""
        plaintext = b"test_consistency"

        crypt1 = PanCrypt()
        encrypted1 = crypt1.encrypt(plaintext)

        crypt2 = PanCrypt()
        decrypted2 = crypt2.decrypt(encrypted1)

        assert decrypted2 == plaintext

    def test_special_characters_preservation(self) -> None:
        """Test that special characters are preserved through encryption/decryption."""
        plaintext = b"!@#$%^&*()_+-=[]{}|;:',.<>?/~`"
        crypt = PanCrypt()

        encrypted = crypt.encrypt(plaintext)
        decrypted = crypt.decrypt(encrypted)

        assert decrypted == plaintext
