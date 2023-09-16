# Enigfile

Encrypt/Decrypt files using password

## Design

* simple format
* chunks for efficient streaming in large file and detection of corruption
* 8-megabytes chunks
* uses chacha20, poly1305 and argon2 as cryptographic primitives

## file format

header (40 bytes):

1. 8 bytes magic 'ENIGFILE'
2. 1 byte version: only 0x30 ('0') defined
3. 15 bytes of 0 - reserved for future extension
4. 16 bytes of entropy / random bytes

for each chunks (chunk data length + 20 bytes + 0-3 bytes padding):

1. 4 bytes: length (big endian)
2. 16 bytes: authenticated tag of the following output
3. length bytes of data
4. 0 to 3 bytes pad: bytes so that the end offset is 32 bits aligned (0 byte if the end byte of data is already aligned).

## Cryptography

the password is processed using Argon2 Key Derivation Function (KDF), using the following parameters:

* Argon2d
* 128kb of memory
* 1 level of parallelism
* 4 iterations

using the file global random (16 bytes) as salt, no bytes of AAD.

the output is 44 bytes and is used as 32 bytes key and 12 bytes nonce for the
chacha20 symmetric cipher.  This stream cipher is used to generate keystream of
44 bytes elements that are used to create context for each 8 megabytes chunks of
data to encrypt (or decrypt).

The chunk context is 44 bytes used also as 32 bytes key and 12 bytes nonce, for
the chacha20poly1035 symmetric authenticated cipher.
