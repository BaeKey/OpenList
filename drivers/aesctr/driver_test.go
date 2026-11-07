package aesctr

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/OpenListTeam/OpenList/v4/internal/model"
	"github.com/OpenListTeam/OpenList/v4/internal/op"
	"github.com/OpenListTeam/OpenList/v4/internal/stream"
	"github.com/OpenListTeam/OpenList/v4/pkg/http_range"
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
	copy(out, fileMagic[:])
	out[len(fileMagic)] = formatVersion
	copy(out[7:], iv)
	cipher.NewCTR(block, iv).XORKeyStream(out[headerSize:], plain)
	return out
}
func decryptFixture(t *testing.T, d *AESCTR, data []byte, offset, length int64) ([]byte, error) {
	t.Helper()
	if len(data) < headerSize {
		return nil, io.ErrUnexpectedEOF
	}
	iv, err := parseHeader(data[:headerSize])
	if err != nil {
		return nil, err
	}
	plainLen := int64(len(data) - headerSize)
	rr := stream.RangeReaderFunc(func(_ context.Context, r http_range.Range) (io.ReadCloser, error) {
		start := r.Start
		if start < 0 || start > int64(len(data)) {
			return nil, io.ErrUnexpectedEOF
		}
		end := int64(len(data))
		if r.Length >= 0 && r.Length < end-start {
			end = start + r.Length
		}
		return io.NopCloser(bytes.NewReader(data[start:end])), nil
	})
	reader, err := d.decryptRange(t.Context(), rr, iv, offset, length, plainLen)
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	return io.ReadAll(reader)
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
	x, err := a.nameEncrypt("hello.txt", false)
	if err != nil {
		t.Fatal(err)
	}
	again, err := a.nameEncrypt("hello.txt", false)
	if err != nil {
		t.Fatal(err)
	}
	if x != again {
		t.Fatal("name encryption is not deterministic")
	}
	other, err := b.nameEncrypt("hello.txt", false)
	if err != nil {
		t.Fatal(err)
	}
	if x == other {
		t.Fatal("different passwords produced same ciphertext")
	}
	if name, err := a.nameDecrypt(x, false); err != nil || name != "hello.txt" {
		t.Fatalf("round trip %q, %v", name, err)
	}
	if _, err := b.nameDecrypt(x, false); err == nil {
		t.Fatal("name encrypted with a different password was accepted")
	}
}

func TestFilenameIVIsNameSpecific(t *testing.T) {
	d := testDriver(t, "pw")
	first, err := d.nameEncrypt("alpha.txt", false)
	if err != nil {
		t.Fatal(err)
	}
	second, err := d.nameEncrypt("bravo.txt", false)
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("different names produced identical encrypted names")
	}
	decodeIV := func(encoded string) []byte {
		t.Helper()
		if !bytes.HasPrefix([]byte(encoded), []byte(encryptedNamePrefix)) {
			t.Fatalf("missing version marker in %q", encoded)
		}
		raw, err := base64.RawURLEncoding.DecodeString(encoded[len(encryptedNamePrefix):])
		if err != nil {
			t.Fatal(err)
		}
		return raw[:aes.BlockSize]
	}
	if bytes.Equal(decodeIV(first), decodeIV(second)) {
		t.Fatal("different names reused the same IV")
	}
	if _, err := d.nameDecrypt("video", false); err == nil {
		t.Fatal("unversioned name was accepted as encrypted")
	}
}

func TestDecryptReaderReturnsUnexpectedEOFWhenTruncated(t *testing.T) {
	d := testDriver(t, "pw")
	block, err := aes.NewCipher(d.key)
	if err != nil {
		t.Fatal(err)
	}
	reader := &decryptReader{
		Reader:    bytes.NewReader([]byte{1, 2, 3}),
		stream:    cipher.NewCTR(block, make([]byte, aes.BlockSize)),
		remaining: 5,
	}
	got, err := io.ReadAll(reader)
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("truncated read error = %v, want %v", err, io.ErrUnexpectedEOF)
	}
	if len(got) != 3 {
		t.Fatalf("got %d bytes before truncation, want 3", len(got))
	}
}

func TestDecryptReaderAcceptsCompleteRange(t *testing.T) {
	d := testDriver(t, "pw")
	block, err := aes.NewCipher(d.key)
	if err != nil {
		t.Fatal(err)
	}
	reader := &decryptReader{
		Reader:    bytes.NewReader([]byte{1, 2, 3}),
		stream:    cipher.NewCTR(block, make([]byte, aes.BlockSize)),
		remaining: 3,
	}
	if _, err := io.ReadAll(reader); err != nil {
		t.Fatalf("complete range returned error: %v", err)
	}
}

func TestSizeCheckReader(t *testing.T) {
	for _, test := range []struct {
		name string
		data string
		want int64
		fail bool
	}{
		{name: "exact", data: "stream", want: 6},
		{name: "short", data: "short", want: 6, fail: true},
		{name: "long", data: "too long", want: 6, fail: true},
		{name: "unknown", data: "stream", want: -1},
	} {
		t.Run(test.name, func(t *testing.T) {
			reader := &sizeCheckReader{Reader: bytes.NewReader([]byte(test.data)), want: test.want}
			got, err := io.ReadAll(reader)
			if (err != nil) != test.fail {
				t.Fatalf("read error = %v, want failure %v", err, test.fail)
			}
			if string(got) != test.data {
				t.Fatalf("read %q, want %q", got, test.data)
			}
		})
	}
}

func TestTamperedV3NameRejected(t *testing.T) {
	d := testDriver(t, "pw")
	encoded, err := d.nameEncrypt("secret.txt", false)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(encoded[len(encryptedNamePrefix):])
	if err != nil {
		t.Fatal(err)
	}
	raw[aes.BlockSize] ^= 1
	tampered := encryptedNamePrefix + base64.RawURLEncoding.EncodeToString(raw)
	if _, err := d.nameDecrypt(tampered, false); err == nil {
		t.Fatal("tampered v3 name was accepted")
	}
}

func TestEncryptedNameLengthLimit(t *testing.T) {
	d := testDriver(t, "pw")
	if err := d.validateNameLength(strings.Repeat("a", 172)); err != nil {
		t.Fatalf("172-byte name rejected: %v", err)
	}
	if err := d.validateNameLength(strings.Repeat("a", 173)); err == nil {
		t.Fatal("173-byte name exceeded the component limit without error")
	}
	d.FileName = false
	if err := d.validateNameLength(strings.Repeat("a", 255)); err != nil {
		t.Fatalf("255-byte unencrypted name rejected: %v", err)
	}
	if err := d.validateNameLength(strings.Repeat("a", 256)); err == nil {
		t.Fatal("unencrypted name exceeded the component limit without error")
	}
}

func TestUnencryptedNamesRemainUnchanged(t *testing.T) {
	d := testDriver(t, "pw")
	d.FileName = false
	name, err := d.nameEncrypt("clear-name.txt", false)
	if err != nil {
		t.Fatal(err)
	}
	if name != "clear-name.txt" {
		t.Fatalf("unencrypted filename changed to %q", name)
	}
	if got, err := d.nameDecrypt(name, false); err != nil || got != "clear-name.txt" {
		t.Fatalf("marked name round trip %q, %v", got, err)
	}
}

func TestEncryptedDirPathTreatsEverySegmentAsDirectory(t *testing.T) {
	d := testDriver(t, "pw")
	got, err := d.encPath("/v1.2/video", true)
	if err != nil {
		t.Fatal(err)
	}
	first, err := d.nameEncrypt("v1.2", true)
	if err != nil {
		t.Fatal(err)
	}
	second, err := d.nameEncrypt("video", true)
	if err != nil {
		t.Fatal(err)
	}
	if want := first + "/" + second; got != want {
		t.Fatalf("encrypted directory path = %q, want %q", got, want)
	}
}

func TestGeneratedSaltIsSavedBeforeKeyDerivation(t *testing.T) {
	var saved string
	original := saveConfig
	saveConfig = func(d *AESCTR) error {
		if len(d.key) != 0 {
			t.Fatal("key was derived before saving the generated salt")
		}
		saved = d.Salt
		return nil
	}
	t.Cleanup(func() { saveConfig = original })

	first := &AESCTR{Addition: Addition{Password: "pw", Time: 1, Memory: 8 * 1024, Threads: 1}}
	if err := first.Init(t.Context()); err != nil {
		t.Fatal(err)
	}
	if saved == "" || saved != first.Salt {
		t.Fatal("generated salt was not saved")
	}
	second := &AESCTR{Addition: Addition{Password: "pw", Salt: saved, Time: 1, Memory: 8 * 1024, Threads: 1}}
	if err := second.Init(t.Context()); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.key, second.key) {
		t.Fatal("reinitializing with persisted salt derived a different key")
	}
}

func TestSaveFailureAbortsInit(t *testing.T) {
	original := saveConfig
	saveConfig = func(*AESCTR) error { return errors.New("boom") }
	t.Cleanup(func() { saveConfig = original })

	d := &AESCTR{Addition: Addition{Password: "pw", Time: 1, Memory: 8 * 1024, Threads: 1}}
	if err := d.Init(t.Context()); err == nil {
		t.Fatal("Init succeeded although the salt could not be saved")
	}
	if len(d.key) != 0 {
		t.Fatal("key was derived although the salt could not be saved")
	}
}

func TestGetRoot(t *testing.T) {
	d := &AESCTR{Addition: Addition{RemotePath: "/encrypted"}}
	root, err := d.Get(t.Context(), "/")
	if err != nil {
		t.Fatal(err)
	}
	if root.GetPath() != "/encrypted" || root.GetName() != op.RootName || !root.IsDir() || model.GetObjMask(root)&model.Locked == 0 {
		t.Fatalf("unexpected root object: %#v", root)
	}
}
