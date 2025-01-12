# Palo Alto Networks Secret Decryptor

A utility to decrypt secrets in a Palo Alto Networks firewall configuration that
have been decrypted with a master key.

Based on:
[paloaltokeys](https://github.com/danielcuthbert/random_scrapers/blob/main/paloaltokeys.py)


## Installation

```sh
pip install -r requirements.txt
```

## Usage

The master key is a 16 character string.

Decrypt using the default master key `p1a2l3o4a5l6t7o8`.
Note `--` is required because the key from the firewall configuration starts
with a `-`.

```sh
$ python palo_secret_decryptor.py -- -AQ==4oaXexPxqJ4g0EWSB1RdFf4eugg=QB2FTzPzPnegOOdK2VtojQ==
secret: letmein123
```

Example of an alternate master key being supplied:

```sh
$ python palo_secret_decryptor.py --master-key 1234567812345678 -- -AQ==4oaXexPxqJ4g0EWSB1RdFf4eugg=yicd7NMQ47s6u8/GgByLMQ==
secret: letmein123
```

Example of an incorrect master key being supplied:

```sh
$ python palo_secret_decryptor.py --master-key p1a2l3o4a5l6t7o9 -- -AQ==4oaXexPxqJ4g0EWSB1RdFf4eugg=QB2FTzPzPnegOOdK2VtojQ==
sha1: e286977b13f1a89e20d0459207545d15fe1eba08
Error: Incorrect Master Key
```
