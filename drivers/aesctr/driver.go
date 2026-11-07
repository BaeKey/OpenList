package aesctr

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	stdpath "path"
	"strings"
	"sync"

	"github.com/OpenListTeam/OpenList/v4/internal/driver"
	"github.com/OpenListTeam/OpenList/v4/internal/errs"
	"github.com/OpenListTeam/OpenList/v4/internal/fs"
	"github.com/OpenListTeam/OpenList/v4/internal/model"
	"github.com/OpenListTeam/OpenList/v4/internal/op"
	"github.com/OpenListTeam/OpenList/v4/internal/stream"
	"github.com/OpenListTeam/OpenList/v4/pkg/http_range"
	"github.com/OpenListTeam/OpenList/v4/pkg/utils"
	"golang.org/x/crypto/argon2"
)

const (
	headerSize    = 23
	formatVersion = 1
)

var fileMagic = [6]byte{'O', 'L', 'A', 'E', 'S', '1'}

var saveConfig = func(d *AESCTR) error { return op.SaveDriverStorage(d) }

type AESCTR struct {
	model.Storage
	Addition
	key                []byte
	contentBlock       cipher.Block
	fileNameKey        []byte
	directoryNameKey   []byte
	fileNameIVKey      []byte
	directoryNameIVKey []byte
}

func (d *AESCTR) Config() driver.Config          { return config }
func (d *AESCTR) GetAddition() driver.Additional { return &d.Addition }
func (d *AESCTR) Init(context.Context) error {
	if d.Password == "" {
		return errors.New("password is required")
	}
	if d.Time == 0 {
		d.Time = 3
	}
	if d.Memory == 0 {
		d.Memory = 64 * 1024
	}
	if d.Threads == 0 {
		d.Threads = 4
	}
	if err := d.ensureSalt(); err != nil {
		return err
	}
	salt, err := base64.RawStdEncoding.DecodeString(d.Salt)
	if err != nil || len(salt) < 8 {
		return errors.New("salt must be valid base64 and contain at least 8 bytes")
	}
	if d.Memory < 8*uint32(d.Threads) {
		return errors.New("argon2 memory is too small for thread count")
	}
	d.key = argon2.IDKey([]byte(d.Password), salt, d.Time, d.Memory, d.Threads, 32)
	d.contentBlock, err = aes.NewCipher(d.key)
	if err != nil {
		return fmt.Errorf("create file cipher: %w", err)
	}
	d.fileNameKey = deriveNameKey(d.key, namePurpose(false))
	d.directoryNameKey = deriveNameKey(d.key, namePurpose(true))
	d.fileNameIVKey = deriveNameIVKey(d.key, namePurpose(false))
	d.directoryNameIVKey = deriveNameIVKey(d.key, namePurpose(true))
	d.RemotePath = utils.FixAndCleanPath(d.RemotePath)
	return nil
}

func (d *AESCTR) ensureSalt() error {
	if d.Salt != "" {
		return nil
	}
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return fmt.Errorf("generate salt: %w", err)
	}
	d.Salt = base64.RawStdEncoding.EncodeToString(b)
	if err := saveConfig(d); err != nil {
		d.Salt = ""
		return fmt.Errorf("persist generated salt: %w", err)
	}
	return nil
}
func (*AESCTR) Drop(context.Context) error { return nil }

const encryptedNamePrefix = "!v3!"
const maxEncryptedNameBytes = 255

// namePurpose separates file and directory name encryption domains.
func namePurpose(directory bool) string {
	if directory {
		return "directory-name"
	}
	return "file-name"
}

func (d *AESCTR) nameKey(directory bool) []byte {
	if directory {
		return d.directoryNameKey
	}
	return d.fileNameKey
}

func (d *AESCTR) nameIVKey(directory bool) []byte {
	if directory {
		return d.directoryNameIVKey
	}
	return d.fileNameIVKey
}

func deriveNameKey(key []byte, purpose string) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte("OpenList AESCTR name key\x00" + purpose))
	return mac.Sum(nil)
}

func deriveNameIVKey(key []byte, purpose string) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte("OpenList AESCTR name IV key\x00" + purpose))
	return mac.Sum(nil)
}

func (d *AESCTR) nameIV(name string, directory bool) []byte {
	purpose := namePurpose(directory)
	mac := hmac.New(sha256.New, d.nameIVKey(directory))
	_, _ = mac.Write([]byte("OpenList AESCTR name IV\x00" + purpose + "\x00" + name))
	return mac.Sum(nil)[:aes.BlockSize]
}

func (d *AESCTR) validateNameLength(name string) error {
	encodedLength := len(name)
	if d.FileName {
		encodedLength = len(encryptedNamePrefix) + base64.RawURLEncoding.EncodedLen(aes.BlockSize+len(name))
	}
	if encodedLength > maxEncryptedNameBytes {
		return fmt.Errorf("encrypted name is %d bytes, exceeding the conservative %d-byte component limit; shorten the name", encodedLength, maxEncryptedNameBytes)
	}
	return nil
}

// nameEncrypt uses a deterministic, name-specific HMAC-derived IV and stores
// that IV alongside the ciphertext. Decryption verifies the IV, which detects
// tampering; determinism still leaks equality and permits guessing low-entropy names.
func (d *AESCTR) nameEncrypt(name string, directory bool) (string, error) {
	if !d.FileName {
		return name, nil
	}
	iv := d.nameIV(name, directory)
	block, err := aes.NewCipher(d.nameKey(directory))
	if err != nil {
		return "", fmt.Errorf("create name cipher: %w", err)
	}
	ciphertext := make([]byte, aes.BlockSize+len(name))
	copy(ciphertext, iv)
	cipher.NewCTR(block, iv).XORKeyStream(ciphertext[aes.BlockSize:], []byte(name))
	return encryptedNamePrefix + base64.RawURLEncoding.EncodeToString(ciphertext), nil
}

func (d *AESCTR) nameDecrypt(name string, directory bool) (string, error) {
	if !d.FileName {
		return name, nil
	}
	if !strings.HasPrefix(name, encryptedNamePrefix) {
		return "", errors.New("unsupported encrypted name format")
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(name, encryptedNamePrefix))
	if err != nil {
		return "", fmt.Errorf("decode encrypted name: %w", err)
	}
	if len(raw) < aes.BlockSize {
		return "", errors.New("encrypted name is shorter than its IV")
	}
	iv, ciphertext := raw[:aes.BlockSize], raw[aes.BlockSize:]
	block, err := aes.NewCipher(d.nameKey(directory))
	if err != nil {
		return "", fmt.Errorf("create name cipher: %w", err)
	}
	plain := make([]byte, len(ciphertext))
	cipher.NewCTR(block, iv).XORKeyStream(plain, ciphertext)
	if !hmac.Equal(d.nameIV(string(plain), directory), iv) {
		return "", errors.New("encrypted name authentication failed")
	}
	return string(plain), nil
}

func (d *AESCTR) encPath(p string, isFolder bool) (string, error) {
	if isFolder {
		parts := strings.Split(strings.Trim(p, "/"), "/")
		for i, part := range parts {
			if part == "" {
				continue
			}
			name, err := d.nameEncrypt(part, true)
			if err != nil {
				return "", err
			}
			parts[i] = name
		}
		return strings.Join(parts, "/"), nil
	}
	parent, name := stdpath.Split(p)
	parent, err := d.encPath(parent, true)
	if err != nil {
		return "", err
	}
	name, err = d.nameEncrypt(name, false)
	if err != nil {
		return "", err
	}
	return stdpath.Join(parent, name), nil
}

func (d *AESCTR) decryptObject(parentPath string, o model.Obj) (model.Obj, bool) {
	mask := model.GetObjMask(o)
	if mask&model.Virtual != 0 {
		return o, true
	}
	name, err := d.nameDecrypt(model.UnwrapObjName(o).GetName(), o.IsDir())
	if err != nil {
		return nil, false
	}
	size := o.GetSize()
	if !o.IsDir() {
		if size < int64(headerSize) {
			return nil, false
		}
		size -= headerSize
	}
	return &model.Object{
		Path:     stdpath.Join(parentPath, o.GetName()),
		Name:     name,
		Size:     size,
		Modified: o.ModTime(),
		Ctime:    o.CreateTime(),
		IsFolder: o.IsDir(),
		Mask:     mask &^ model.Temp,
	}, true
}

func (d *AESCTR) List(ctx context.Context, dir model.Obj, args model.ListArgs) ([]model.Obj, error) {
	objs, err := fs.List(ctx, dir.GetPath(), &fs.ListArgs{NoLog: true, Refresh: args.Refresh})
	if err != nil {
		return nil, err
	}
	out := make([]model.Obj, 0, len(objs))
	for _, o := range objs {
		if decoded, ok := d.decryptObject(dir.GetPath(), o); ok {
			out = append(out, decoded)
		}
	}
	return out, nil
}

func (d *AESCTR) Get(ctx context.Context, p string) (model.Obj, error) {
	trimmed := strings.Trim(p, "/")
	if trimmed == "" {
		return d.rootObject(ctx)
	}
	candidates := []bool{strings.HasSuffix(p, "/")}
	if !candidates[0] {
		candidates = append(candidates, true)
	}
	lastErr := errs.ObjectNotFound
	for _, isFolder := range candidates {
		encryptedPath, err := d.encPath(trimmed, isFolder)
		if err != nil {
			return nil, err
		}
		remote := stdpath.Join(d.RemotePath, encryptedPath)
		o, err := fs.Get(ctx, remote, &fs.GetArgs{NoLog: true})
		if err != nil {
			if !errs.IsObjectNotFound(err) {
				return nil, err
			}
			lastErr = err
			continue
		}
		decoded, ok := d.decryptObject(stdpath.Dir(remote), o)
		if !ok {
			return nil, errors.New("invalid AES-CTR object metadata")
		}
		return decoded, nil
	}
	return nil, lastErr
}

func (d *AESCTR) rootObject(context.Context) (model.Obj, error) {
	return &model.Object{
		Path:     d.RemotePath,
		Name:     op.RootName,
		Modified: d.Storage.Modified,
		IsFolder: true,
		Mask:     model.Locked,
	}, nil
}

func parseHeader(header []byte) ([]byte, error) {
	if len(header) != headerSize {
		return nil, fmt.Errorf("invalid AES-CTR header length: got %d, want %d", len(header), headerSize)
	}
	if !bytes.Equal(header[:len(fileMagic)], fileMagic[:]) || header[len(fileMagic)] != formatVersion {
		return nil, errors.New("invalid AES-CTR file header")
	}
	return append([]byte(nil), header[len(fileMagic)+1:]...), nil
}

func addCounter(iv []byte, blocks uint64) {
	for i := len(iv) - 1; i >= 0 && blocks > 0; i-- {
		sum := uint64(iv[i]) + (blocks & 255)
		iv[i] = byte(sum)
		blocks = (blocks >> 8) + (sum >> 8)
	}
}

func (d *AESCTR) decryptRange(ctx context.Context, rr model.RangeReaderIF, baseIV []byte, offset, length, plainSize int64) (io.ReadCloser, error) {
	if offset < 0 {
		return nil, errors.New("negative range offset")
	}
	if len(baseIV) != aes.BlockSize {
		return nil, fmt.Errorf("invalid AES-CTR base IV length: got %d, want %d", len(baseIV), aes.BlockSize)
	}
	if offset >= plainSize || length == 0 {
		return io.NopCloser(strings.NewReader("")), nil
	}
	if length < 0 || length > plainSize-offset {
		length = plainSize - offset
	}
	iv := append([]byte(nil), baseIV...)
	blockOffset := uint64(offset / aes.BlockSize)
	skip := offset % aes.BlockSize
	cipherOffset := int64(headerSize) + offset
	addCounter(iv, blockOffset)
	remote, err := rr.RangeRead(ctx, http_range.Range{Start: cipherOffset, Length: length})
	if err != nil {
		return nil, err
	}
	ctr := cipher.NewCTR(d.contentBlock, iv)
	if skip > 0 {
		scratch := make([]byte, skip)
		ctr.XORKeyStream(scratch, scratch)
	}
	return &decryptReader{Reader: remote, stream: ctr, remaining: length}, nil
}

func (d *AESCTR) Link(ctx context.Context, file model.Obj, _ model.LinkArgs) (*model.Link, error) {
	st, path, err := op.GetStorageAndActualPath(file.GetPath())
	if err != nil {
		return nil, err
	}
	remoteLink, remoteObj, err := op.Link(ctx, st, path, model.LinkArgs{})
	if err != nil {
		return nil, err
	}
	size := remoteLink.ContentLength
	if size <= 0 {
		size = remoteObj.GetSize()
	}
	rr, err := stream.GetRangeReaderFromLink(size, remoteLink)
	if err != nil {
		remoteLink.Close()
		return nil, fmt.Errorf("AES-CTR requires range-capable remote storage: %w", err)
	}
	var headerMu sync.Mutex
	var baseIV []byte
	loadHeader := func(ctx context.Context) ([]byte, error) {
		headerMu.Lock()
		defer headerMu.Unlock()
		if baseIV != nil {
			return append([]byte(nil), baseIV...), nil
		}
		r, e := rr.RangeRead(ctx, http_range.Range{Start: 0, Length: headerSize})
		if e != nil {
			return nil, e
		}
		defer r.Close()
		h := make([]byte, headerSize)
		if _, e = io.ReadFull(r, h); e != nil {
			return nil, fmt.Errorf("read AES-CTR header: %w", e)
		}
		iv, e := parseHeader(h)
		if e != nil {
			return nil, e
		}
		baseIV = iv
		return append([]byte(nil), baseIV...), nil
	}
	reader := stream.RangeReaderFunc(func(ctx context.Context, rng http_range.Range) (io.ReadCloser, error) {
		iv, err := loadHeader(ctx)
		if err != nil {
			return nil, err
		}
		return d.decryptRange(ctx, rr, iv, rng.Start, rng.Length, file.GetSize())
	})
	return &model.Link{RangeReader: reader, ContentLength: file.GetSize(), SyncClosers: utils.NewSyncClosers(remoteLink), RequireReference: remoteLink.RequireReference}, nil
}

type decryptReader struct {
	io.Reader
	stream    cipher.Stream
	remaining int64
}

type sizeCheckReader struct {
	io.Reader
	want int64
	got  int64
}

func (r *sizeCheckReader) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	r.got += int64(n)
	if err == io.EOF && r.want >= 0 && r.got != r.want {
		return n, fmt.Errorf("AES-CTR upload size mismatch: got %d, want %d", r.got, r.want)
	}
	return n, err
}

func (r *decryptReader) Read(p []byte) (int, error) {
	if r.remaining <= 0 {
		return 0, io.EOF
	}
	if int64(len(p)) > r.remaining {
		p = p[:r.remaining]
	}
	n, e := r.Reader.Read(p)
	if n > 0 {
		r.stream.XORKeyStream(p[:n], p[:n])
		r.remaining -= int64(n)
	}
	if e == io.EOF && r.remaining > 0 {
		return n, io.ErrUnexpectedEOF
	}
	return n, e
}
func (r *decryptReader) Close() error {
	if c, ok := r.Reader.(io.Closer); ok {
		return c.Close()
	}
	return nil
}

func (d *AESCTR) MakeDir(ctx context.Context, parent model.Obj, name string) error {
	if err := d.validateNameLength(name); err != nil {
		return err
	}
	st, p, e := op.GetStorageAndActualPath(parent.GetPath())
	if e != nil {
		return e
	}
	encryptedName, e := d.nameEncrypt(name, true)
	if e != nil {
		return e
	}
	return op.MakeDir(ctx, st, stdpath.Join(p, encryptedName))
}
func (d *AESCTR) Move(ctx context.Context, s, t model.Obj) error {
	_, e := fs.Move(ctx, s.GetPath(), t.GetPath())
	return e
}
func (d *AESCTR) Rename(ctx context.Context, s model.Obj, n string) error {
	if err := d.validateNameLength(n); err != nil {
		return err
	}
	st, p, e := op.GetStorageAndActualPath(s.GetPath())
	if e != nil {
		return e
	}
	encryptedName, e := d.nameEncrypt(n, s.IsDir())
	if e != nil {
		return e
	}
	return op.Rename(ctx, st, p, encryptedName)
}
func (d *AESCTR) Copy(ctx context.Context, s, t model.Obj) error {
	_, e := fs.Copy(ctx, s.GetPath(), t.GetPath())
	return e
}
func (d *AESCTR) Remove(ctx context.Context, o model.Obj) error {
	st, p, e := op.GetStorageAndActualPath(o.GetPath())
	if e != nil {
		return e
	}
	return op.Remove(ctx, st, p)
}
func (d *AESCTR) Put(ctx context.Context, dst model.Obj, f model.FileStreamer, up driver.UpdateProgress) error {
	if err := d.validateNameLength(f.GetName()); err != nil {
		return err
	}
	st, p, e := op.GetStorageAndActualPath(dst.GetPath())
	if e != nil {
		return e
	}
	iv := make([]byte, 16)
	if _, e = rand.Read(iv); e != nil {
		return fmt.Errorf("generate file IV: %w", e)
	}
	h := make([]byte, headerSize)
	copy(h, fileMagic[:])
	h[len(fileMagic)] = formatVersion
	copy(h[7:], iv)
	encrypted := cipher.StreamReader{S: cipher.NewCTR(d.contentBlock, iv), R: f}
	expectedSize := f.GetSize()
	if expectedSize >= 0 {
		expectedSize += headerSize
	}
	r := &sizeCheckReader{Reader: io.MultiReader(bytes.NewReader(h), encrypted), want: expectedSize}
	encryptedName, e := d.nameEncrypt(f.GetName(), false)
	if e != nil {
		return e
	}
	out := &stream.FileStream{Obj: &model.Object{ID: f.GetID(), Path: f.GetPath(), Name: encryptedName, Size: expectedSize, Modified: f.ModTime()}, Reader: r, Mimetype: "application/octet-stream", ForceStreamUpload: true, Exist: f.GetExist()}
	return op.Put(ctx, st, p, out, up)
}

var _ driver.Driver = (*AESCTR)(nil)
