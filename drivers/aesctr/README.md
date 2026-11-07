# AESCTR storage format

Each file is stored as a 23-byte header followed by AES-256-CTR ciphertext:

- bytes 0–5: `OLAES1` magic
- byte 6: format version (`1`)
- bytes 7–22: random 16-byte base IV

The AES-256 key is derived from the configured password and persisted Base64 salt with Argon2id. Argon2 time, memory (KiB), and thread parameters are configurable. If salt is blank at initialization, a random 16-byte salt is generated and written back to the addition configuration. Storage initialization fails if the updated configuration cannot be persisted.

Range reads request ciphertext beginning at `23 + offset`, add `floor(offset/16)` to the base IV as a 128-bit big-endian counter, discard the first `offset mod 16` keystream bytes, then decrypt the requested bytes. A short Range response returns `io.ErrUnexpectedEOF`. Stored size is plaintext size plus 23 bytes. Upload streams check the total ciphertext length at EOF and fail the upload when a known source size does not match.

Names use deterministic AES-CTR with purpose-specific encryption and IV subkeys derived from the Argon2id key. The name-specific IV is derived by HMAC-SHA256 over the plaintext name and stored with the ciphertext under a `!v3!` marker; on decryption, the driver recomputes and compares the IV. This detects tampering or a wrong password while avoiding keystream reuse between different names. Only the authenticated `!v3!` format is accepted. Determinism leaks repeated names and permits guessing low-entropy names. The driver rejects encrypted names longer than 255 bytes; with this encoding, that limits original UTF-8 names to 172 bytes. Filenames and directory names share the `filename_encryption` option.

When filename encryption is disabled, names remain visible while file contents are still encrypted. Do not mix ordinary plaintext files into the AESCTR remote directory in this mode, because the format has no filename marker to distinguish them.

This format does not authenticate ciphertext. A wrong password, bit flips, and malicious modifications to encrypted content are not detected; only the magic and version are checked. Store backups of the password, salt, and Argon2 parameters together, since losing them makes data unreadable.
