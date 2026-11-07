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
	"github.com/OpenListTeam/OpenList/v4/internal/fs"
	"github.com/OpenListTeam/OpenList/v4/internal/model"
	"github.com/OpenListTeam/OpenList/v4/internal/op"
	"github.com/OpenListTeam/OpenList/v4/internal/stream"
	"github.com/OpenListTeam/OpenList/v4/pkg/http_range"
	"github.com/OpenListTeam/OpenList/v4/pkg/utils"
	"golang.org/x/crypto/argon2"
)

const headerSize = 23

var magic = [6]byte{'O', 'L', 'A', 'E', 'S', '1'}

type AESCTR struct {
	model.Storage
	Addition
	key []byte
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
	if d.Salt == "" {
		b := make([]byte, 16)
		if _, err := rand.Read(b); err != nil {
			return fmt.Errorf("generate salt: %w", err)
		}
		d.Salt = base64.RawStdEncoding.EncodeToString(b)
	}
	salt, err := base64.RawStdEncoding.DecodeString(d.Salt)
	if err != nil || len(salt) < 8 {
		return errors.New("salt must be valid base64 and contain at least 8 bytes")
	}
	if d.Memory < 8*uint32(d.Threads) {
		return errors.New("argon2 memory is too small for thread count")
	}
	d.key = argon2.IDKey([]byte(d.Password), salt, d.Time, d.Memory, d.Threads, 32)
	d.RemotePath = utils.FixAndCleanPath(d.RemotePath)
	return nil
}
func (*AESCTR) Drop(context.Context) error { return nil }

// nameEncrypt uses deterministic AES-CTR with an HMAC-derived IV so a name maps
// consistently for lookup. This leaks equality and is unauthenticated; it is
// suitable for path compatibility, not for protecting low-entropy names against
// guessing or detecting tampering.
func (d *AESCTR) nameEncrypt(name string, directory bool) string {
	if !d.FileName {
		return name
	}
	purpose := "file-name"
	if directory {
		purpose = "directory-name"
	}
	mac := hmac.New(sha256.New, d.key)
	mac.Write([]byte(purpose))
	sum := mac.Sum(nil)
	block, _ := aes.NewCipher(d.key)
	iv := sum[:aes.BlockSize]
	out := make([]byte, len(name))
	cipher.NewCTR(block, iv).XORKeyStream(out, []byte(name))
	return base64.RawURLEncoding.EncodeToString(out)
}
func (d *AESCTR) nameDecrypt(name string, directory bool) (string, error) {
	if !d.FileName {
		return name, nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(name)
	if err != nil {
		return "", err
	}
	purpose := "file-name"
	if directory {
		purpose = "directory-name"
	}
	mac := hmac.New(sha256.New, d.key)
	mac.Write([]byte(purpose))
	iv := mac.Sum(nil)[:aes.BlockSize]
	block, _ := aes.NewCipher(d.key)
	cipher.NewCTR(block, iv).XORKeyStream(raw, raw)
	return string(raw), nil
}
func (d *AESCTR) encPath(p string, dir bool) string {
	if dir {
		parts := strings.Split(strings.Trim(p, "/"), "/")
		for i := range parts {
			if parts[i] != "" {
				parts[i] = d.nameEncrypt(parts[i], true)
			}
		}
		return strings.Join(parts, "/")
	}
	parent, name := stdpath.Split(p)
	return stdpath.Join(d.encPath(parent, true), d.nameEncrypt(name, false))
}

func (d *AESCTR) List(ctx context.Context, dir model.Obj, args model.ListArgs) ([]model.Obj, error) {
	objs, err := fs.List(ctx, dir.GetPath(), &fs.ListArgs{NoLog: true, Refresh: args.Refresh})
	if err != nil {
		return nil, err
	}
	out := make([]model.Obj, 0, len(objs))
	for _, o := range objs {
		mask := model.GetObjMask(o)
		if mask&model.Virtual != 0 {
			out = append(out, o)
			continue
		}
		name := o.GetName()
		size := o.GetSize()
		if o.IsDir() {
			name, err = d.nameDecrypt(model.UnwrapObjName(o).GetName(), true)
		} else {
			name, err = d.nameDecrypt(model.UnwrapObjName(o).GetName(), false)
			if size < int64(headerSize) {
				continue
			}
			size -= headerSize
		}
		if err != nil {
			continue
		}
		out = append(out, &model.Object{Path: stdpath.Join(dir.GetPath(), o.GetName()), Name: name, Size: size, Modified: o.ModTime(), Ctime: o.CreateTime(), IsFolder: o.IsDir(), Mask: mask &^ model.Temp})
	}
	return out, nil
}
func (d *AESCTR) Get(ctx context.Context, p string) (model.Obj, error) {
	remote := stdpath.Join(d.RemotePath, d.encPath(p, strings.HasSuffix(p, "/")))
	o, err := fs.Get(ctx, remote, &fs.GetArgs{NoLog: true})
	if err != nil {
		return nil, err
	}
	name := o.GetName()
	size := o.GetSize()
	mask := model.GetObjMask(o)
	if mask&model.Virtual == 0 {
		if o.IsDir() {
			name, err = d.nameDecrypt(model.UnwrapObjName(o).GetName(), true)
		} else {
			name, err = d.nameDecrypt(model.UnwrapObjName(o).GetName(), false)
			if size < int64(headerSize) {
				return nil, fmt.Errorf("invalid AES-CTR object size")
			}
			size -= headerSize
		}
	}
	if err != nil {
		return nil, err
	}
	return &model.Object{Path: remote, Name: name, Size: size, Modified: o.ModTime(), Ctime: o.CreateTime(), IsFolder: o.IsDir(), Mask: mask}, nil
}

func addCounter(iv []byte, blocks uint64) {
	for i := len(iv) - 1; i >= 0 && blocks > 0; i-- {
		sum := uint64(iv[i]) + (blocks & 255)
		iv[i] = byte(sum)
		blocks = (blocks >> 8) + (sum >> 8)
	}
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
	var once sync.Once
	var headErr error
	var baseIV []byte
	loadHeader := func(ctx context.Context) error {
		once.Do(func() {
			r, e := rr.RangeRead(ctx, http_range.Range{Start: 0, Length: headerSize})
			if e != nil {
				headErr = e
				return
			}
			defer r.Close()
			h := make([]byte, headerSize)
			if _, e = io.ReadFull(r, h); e != nil {
				headErr = fmt.Errorf("read AES-CTR header: %w", e)
				return
			}
			if string(h[:6]) != string(magic[:]) || h[6] != 1 {
				headErr = errors.New("invalid AES-CTR file header")
				return
			}
			baseIV = append([]byte(nil), h[7:]...)
		})
		return headErr
	}
	reader := stream.RangeReaderFunc(func(ctx context.Context, rng http_range.Range) (io.ReadCloser, error) {
		if err := loadHeader(ctx); err != nil {
			return nil, err
		}
		if rng.Start < 0 {
			return nil, errors.New("negative range offset")
		}
		if rng.Start >= file.GetSize() {
			return io.NopCloser(strings.NewReader("")), nil
		}
		length := rng.Length
		if length < 0 || rng.Start+length > file.GetSize() {
			length = file.GetSize() - rng.Start
		}
		blockOff := rng.Start / 16
		skip := rng.Start % 16
		iv := append([]byte(nil), baseIV...)
		addCounter(iv, uint64(blockOff))
		cipherOffset := int64(headerSize) + blockOff*16
		remote, e := rr.RangeRead(ctx, http_range.Range{Start: cipherOffset, Length: skip + length})
		if e != nil {
			return nil, e
		}
		block, _ := aes.NewCipher(d.key)
		ctr := cipher.NewCTR(block, iv)
		if skip > 0 {
			dummy := make([]byte, skip)
			ctr.XORKeyStream(dummy, dummy)
		}
		return &decryptReader{Reader: remote, stream: ctr, remaining: length}, nil
	})
	return &model.Link{RangeReader: reader, ContentLength: file.GetSize(), SyncClosers: utils.NewSyncClosers(remoteLink), RequireReference: remoteLink.RequireReference}, nil
}

type decryptReader struct {
	io.Reader
	stream    cipher.Stream
	remaining int64
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
	return n, e
}
func (r *decryptReader) Close() error {
	if c, ok := r.Reader.(io.Closer); ok {
		return c.Close()
	}
	return nil
}

func (d *AESCTR) MakeDir(ctx context.Context, parent model.Obj, name string) error {
	st, p, e := op.GetStorageAndActualPath(parent.GetPath())
	if e != nil {
		return e
	}
	return op.MakeDir(ctx, st, stdpath.Join(p, d.nameEncrypt(name, true)))
}
func (d *AESCTR) Move(ctx context.Context, s, t model.Obj) error {
	_, e := fs.Move(ctx, s.GetPath(), t.GetPath())
	return e
}
func (d *AESCTR) Rename(ctx context.Context, s model.Obj, n string) error {
	st, p, e := op.GetStorageAndActualPath(s.GetPath())
	if e != nil {
		return e
	}
	return op.Rename(ctx, st, p, d.nameEncrypt(n, s.IsDir()))
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
func encryptedSize(size int64) int64 {
	if size < 0 {
		return size
	}
	return size + headerSize
}

func (d *AESCTR) Put(ctx context.Context, dst model.Obj, f model.FileStreamer, up driver.UpdateProgress) error {
	st, p, e := op.GetStorageAndActualPath(dst.GetPath())
	if e != nil {
		return e
	}
	iv := make([]byte, 16)
	if _, e = rand.Read(iv); e != nil {
		return fmt.Errorf("generate file IV: %w", e)
	}
	h := make([]byte, headerSize)
	copy(h, magic[:])
	h[6] = 1
	copy(h[7:], iv)
	block, _ := aes.NewCipher(d.key)
	encrypted := cipher.StreamReader{S: cipher.NewCTR(block, iv), R: f}
	r := io.MultiReader(bytes.NewReader(h), encrypted)
	out := &stream.FileStream{Obj: &model.Object{ID: f.GetID(), Path: f.GetPath(), Name: d.nameEncrypt(f.GetName(), false), Size: encryptedSize(f.GetSize()), Modified: f.ModTime()}, Reader: r, Mimetype: "application/octet-stream", ForceStreamUpload: true, Exist: f.GetExist()}
	return op.Put(ctx, st, p, out, up)
}

var _ driver.Driver = (*AESCTR)(nil)
