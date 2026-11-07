package aesctr

import (
	"github.com/OpenListTeam/OpenList/v4/internal/driver"
	"github.com/OpenListTeam/OpenList/v4/internal/op"
)

type Addition struct {
	Password   string `json:"password" required:"true" confidential:"true"`
	Salt       string `json:"salt" confidential:"true" help:"Base64 salt; generated on first initialization when empty and persisted with the storage"`
	Time       uint32 `json:"argon2_time" type:"number" default:"3"`
	Memory     uint32 `json:"argon2_memory" type:"number" default:"65536" help:"Argon2 memory in KiB"`
	Threads    uint8  `json:"argon2_threads" type:"number" default:"4"`
	FileName   bool   `json:"filename_encryption" default:"true" help:"Encrypt file and directory names; file contents are always encrypted"`
	RemotePath string `json:"remote_path" required:"true" help:"Remote path storing encrypted data"`
}

var config = driver.Config{Name: "AESCTR", LocalSort: true, OnlyProxy: true, NoCache: true, DefaultRoot: "/", NoLinkURL: true, CheckStatus: true}

func (a Addition) GetRootPath() string { return a.RemotePath }

func init() { op.RegisterDriver(func() driver.Driver { return &AESCTR{} }) }
