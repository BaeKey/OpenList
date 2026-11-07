package aesctr

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"io"
	"testing"
)

func testDriver(t *testing.T, password string) *AESCTR {
	t.Helper()
	d := &AESCTR{Addition: Addition{Password: password, Salt: base64.RawStdEncoding.EncodeToString([]byte("0123456789abcdef")), Time: 1, Memory: 8 * 1024, Threads: 1, FileName: true}}
	if err := d.Init(t.Context()); err != nil {
		t.Fatal(err)
	}
	return d
}

func encryptFixture(t *testing.T, d *AESCTR, plain []byte) []byte {
	t.Helper()
	iv := make([]byte, 16)
	if _, err := rand.Read(iv); err != nil {
		t.Fatal(err)
	}
	block, _ := aes.NewCipher(d.key)
	out := make([]byte, headerSize+len(plain))
	copy(out, magic[:])
	out[6] = 1
	copy(out[7:], iv)
	cipher.NewCTR(block, iv).XORKeyStream(out[headerSize:], plain)
	return out
}
func decryptFixture(t *testing.T, d *AESCTR, data []byte, offset, length int64) ([]byte, error) {
	t.Helper()
	if len(data) < headerSize || !bytes.Equal(data[:6], magic[:]) || data[6] != 1 {
		return nil, io.ErrUnexpectedEOF
	}
	plainLen := int64(len(data) - headerSize)
	if offset < 0 {
		return nil, io.ErrUnexpectedEOF
	}
	if offset >= plainLen {
		return []byte{}, nil
	}
	if length < 0 || offset+length > plainLen {
		length = plainLen - offset
	}
	blockOff, skip := offset/16, offset%16
	iv := append([]byte(nil), data[7:headerSize]...)
	addCounter(iv, uint64(blockOff))
	start := int64(headerSize) + blockOff*16
	ciphertext := data[start : start+skip+length]
	block, _ := aes.NewCipher(d.key)
	ctr := cipher.NewCTR(block, iv)
	discard := make([]byte, skip)
	ctr.XORKeyStream(discard, discard)
	out := append([]byte(nil), ciphertext[skip:]...)
	ctr.XORKeyStream(out, out)
	return out, nil
}
func TestEncryptDecryptAndRanges(t *testing.T) {
	d := testDriver(t, "pw")
	for _, size := range []int{0, 1, 15, 16, 17, 1<<20 + 7} {
		plain := make([]byte, size)
		if _, err := rand.Read(plain); err != nil {
			t.Fatal(err)
		}
		enc := encryptFixture(t, d, plain)
		got, err := decryptFixture(t, d, enc, 0, -1)
		if err != nil || !bytes.Equal(got, plain) {
			t.Fatalf("size %d: decrypt mismatch, err=%v", size, err)
		}
		for _, off := range []int64{0, 1, 15, 16, 17, int64(size / 2), int64(size)} {
			if off > int64(size) {
				continue
			}
			length := int64(29)
			got, err = decryptFixture(t, d, enc, off, length)
			if err != nil {
				t.Fatal(err)
			}
			end := off + length
			if end > int64(size) {
				end = int64(size)
			}
			if !bytes.Equal(got, plain[off:end]) {
				t.Fatalf("size %d offset %d: range mismatch", size, off)
			}
		}
	}
}
func TestHeaderValidation(t *testing.T) {
	d := testDriver(t, "pw")
	b := encryptFixture(t, d, []byte("x"))
	for _, mutate := range []func([]byte){func(b []byte) { b[0] ^= 1 }, func(b []byte) { b[6] = 2 }} {
		bad := append([]byte(nil), b...)
		mutate(bad)
		if _, err := decryptFixture(t, d, bad, 0, -1); err == nil {
			t.Fatal("invalid header accepted")
		}
	}
}
func TestDeterministicNames(t *testing.T) {
	a := testDriver(t, "one")
	b := testDriver(t, "two")
	x := a.nameEncrypt("hello.txt", false)
	if x != a.nameEncrypt("hello.txt", false) {
		t.Fatal("name encryption is not deterministic")
	}
	if x == b.nameEncrypt("hello.txt", false) {
		t.Fatal("different passwords produced same ciphertext")
	}
	if name, err := a.nameDecrypt(x, false); err != nil || name != "hello.txt" {
		t.Fatalf("round trip %q, %v", name, err)
	}
}
