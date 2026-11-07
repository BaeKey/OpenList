# AESCTR storage format

Each file is stored as a 23-byte header followed by AES-256-CTR ciphertext:

- bytes 0–5: `OLAES1` magic
- byte 6: format version (`1`)
- bytes 7–22: random 16-byte base IV

The AES-256 key is derived from the configured password and persisted Base64 salt with Argon2id. Argon2 time, memory (KiB), and thread parameters are configurable. If salt is blank at initialization, a random 16-byte salt is generated and written back to the addition configuration.

Range reads seek to `23 + floor(offset/16)*16`, add `floor(offset/16)` to the base IV as a 128-bit big-endian counter, discard the first `offset mod 16` keystream bytes, then decrypt the requested bytes. Stored size is plaintext size plus 23 bytes.

Names use deterministic AES-CTR with an IV derived by HMAC-SHA256 over a file/directory purpose label. This makes lookup stable but leaks repeated names and permits guessing low-entropy names; it is not a misuse-resistant deterministic encryption scheme. Filenames and directory names share the `filename_encryption` option.

This format does not authenticate ciphertext. A wrong password, bit flips, and malicious modifications to encrypted content are not detected; only the magic and version are checked. Store backups of the password, salt, and Argon2 parameters together, since losing them makes data unreadable.
