package aesctr

import (
	"github.com/OpenListTeam/OpenList/v4/internal/driver"
	"github.com/OpenListTeam/OpenList/v4/internal/op"
)

type Addition struct {
	Password   string `json:"password" required:"true" confidential:"true" type:"password"`
	Salt       string `json:"salt" confidential:"true" help:"Base64 salt; generated on first initialization when empty"`
	Time       uint32 `json:"argon2_time" default:"3"`
	Memory     uint32 `json:"argon2_memory" default:"65536" help:"Argon2 memory in KiB"`
	Threads    uint8  `json:"argon2_threads" default:"4"`
	FileName   bool   `json:"filename_encryption" default:"true"`
	RemotePath string `json:"remote_path" required:"true" help:"Remote path storing encrypted data"`
}

var config = driver.Config{Name: "AESCTR", LocalSort: true, OnlyProxy: true, NoCache: true, DefaultRoot: "/", NoLinkURL: true, CheckStatus: true}

func (a Addition) GetRootPath() string { return a.RemotePath }

func init() { op.RegisterDriver(func() driver.Driver { return &AESCTR{} }) }
