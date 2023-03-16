package main

import (
	"bytes"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/apex/log"
	"github.com/urfave/cli/v2"
)

var (
	errNotImplemented = fmt.Errorf("is not implemented yet")
)

type gc struct {
	gs     *gopassStorage
	sa     *sshAgent
	cb     *clp
	logger log.Logger
	key    string
	yes    bool
}

func (s gc) log() *log.Entry {
	if s.key == "" {
		return log.NewEntry(&s.logger)
	}
	return s.logger.WithField("gkey", s.key)
}

func (s *gc) PathAutocomplete(c *cli.Context) {
	var store = c.String("store")
	ll, err := s.gs.list(store)
	if err != nil {
		panic(err)
	}

	fmt.Println(strings.Join(ll, "\n"))
}

func (s *gc) BeforeBase(c *cli.Context) error {
	var silent = c.Bool("quiet")
	s.yes = c.Bool("yes")

	if silent {
		s.logger.Level = log.ErrorLevel
	}

	return nil
}

// Before is executed before another git-credential command.
func (s *gc) Before(c *cli.Context) error {
	if c.NArg() == 0 {
		return errors.New("ssh-key path must be set")
	}

	store := c.String("store")
	sshKeyPath := c.Args().Get(0)
	s.key = filepath.Join(store, sshKeyPath)

	err := s.BeforeBase(c)
	if err != nil {
		return err
	}

	return nil
}

func (s gc) confirm(q string, qq ...any) bool {
	if s.yes {
		return true
	}

	if res := askForConfirmation(q, qq...); res {
		return true
	}

	s.log().Info("Cancelled")
	return false
}

// SSHAdd - adding ssh-key to ssh-agent
func (s *gc) SSHAdd(c *cli.Context) error {
	s.log().Info("getting private ssh-key from gopass")
	privKey, err := s.gs.getPrivateSSHKey(s.key)
	if err != nil {
		return err
	}

	s.log().Info("getting ssh-key passphrase from gopass")
	password, err := s.gs.getPassword(s.key)
	if err != nil {
		return err
	}

	lifetime := c.Int("lifetime")
	strDur, err := time.ParseDuration(fmt.Sprintf("%ds", lifetime))
	if err != nil {
		return err
	}

	s.log().Infof("adding private ssh-key to ssh-agent for %s", strDur)
	err = s.sa.add(privKey, password, s.key, uint32(lifetime))
	if err != nil {
		return err
	}

	return nil
}

// SSHAdd - delete ssh-key from ssh-agent
func (s *gc) SSHDelete(c *cli.Context) error {
	s.log().Info("getting public ssh-key from gopass")
	pubKey, err := s.gs.getPublicSSHKey(s.key)
	if err != nil {
		return err
	}

	s.log().Info("removing ssh-key from ssh-agent")
	err = s.sa.delete(pubKey)
	if err != nil {
		return err
	}

	return nil
}

// SSHList - show ssh key in ssh-agent (`ssh-add -l`)
func (s *gc) SSHList(c *cli.Context) error {
	s.log().Info("getting ssh-keys list from ssh-agent")
	ll, err := s.sa.list()
	if err != nil {
		return err
	}

	fmt.Println(strings.Join(ll, "\n\n"))
	return nil
}

// SSHClear - delete all ssh keys from ssh-agent (`ssh-add -D`)
func (s *gc) SSHClear(c *cli.Context) error {
	if !s.confirm("Are you sure you want to remove all ssh-keys from ssh-agent?") {
		return nil
	}

	s.log().Info("removing all ssh-keys from ssh-agent")
	err := s.sa.clear()
	if err != nil {
		return err
	}
	return nil
}

// SSHKeygen - generate ssh-key and save it to gopass
func (s *gc) SSHKeygen(c *cli.Context) error {
	var sshKeyType = c.String("type")
	// var sshKeyComment = c.String("comment")
	var sshKeyBits = c.Int("bits")
	var passLen = c.Int("length")
	var includeSymbols = c.Bool("symbols")

	s.log().Infof("generating ssh-key passphrase with length - %d", passLen)
	passwd, err := genPassword(passLen, includeSymbols)
	if err != nil {
		return err
	}

	s.log().Infof("generating %s ssh-keys", sshKeyType)
	privKey, pubKey, err := sshKeygen(sshKeyType, passwd, sshKeyBits)
	if err != nil {
		return err
	}

	if !s.confirm("Are you sure you want to save generated ssh-key and password to gopass ('%s')?", s.key) {
		return nil
	}

	s.log().Info("saving password to gopass")
	err = s.gs.setPassword(s.key, passwd)
	if err != nil {
		return err
	}

	s.log().Info("saving private ssh-key to gopass")
	err = s.gs.setPrivateSSHKey(s.key, privKey)
	if err != nil {
		return err
	}

	s.log().Info("saving public ssh-key to gopass")
	err = s.gs.setPublicSSHKey(s.key, pubKey)
	if err != nil {
		return err
	}

	return nil
}

// Delete - delete ssh-key secret completely
func (s *gc) Delete(c *cli.Context) error {
	var err error

	if !s.confirm("Are you sure you want to DELETE ssh-key secret from gopass ('%s')?", s.key) {
		return nil
	}

	s.log().Info("deleting password gopass secret")
	err = s.gs.delPassword(s.key)
	if err != nil {
		return err
	}

	s.log().Info("deleting private ssh-key gopass secret")
	err = s.gs.delPrivateSSHKey(s.key)
	if err != nil {
		return err
	}

	s.log().Info("deleting public ssh-key gopass secret")
	err = s.gs.delPublicSSHKey(s.key)
	if err != nil {
		return err
	}

	return nil
}

// ShowPassword - show ssh-key password from gopass secret
func (s *gc) ShowPassword(c *cli.Context) error {
	var clip = c.Bool("clipboard")

	s.log().Info("getting password from gopass")
	password, err := s.gs.getPassword(s.key)
	if err != nil {
		return err
	}

	if !clip {
		fmt.Println(password)
		return nil
	}

	fullKey := s.gs.getPasswordPath(s.key)
	err = s.cb.copy(fullKey, []byte(password), 45)
	if err != nil {
		return err
	}

	return nil
}

// DeletePassword - delete ssh-key password from gopass secret
func (s *gc) DeletePassword(c *cli.Context) error {
	var err error

	if !s.confirm("Are you sure you want to DELETE password from gopass ('%s')?", s.key) {
		return nil
	}

	s.log().Info("deleting password from gopass")
	err = s.gs.delPassword(s.key)
	if err != nil {
		return err
	}
	return nil
}

// GeneratePassword - generating ssh-key password and save it in gopass secret
func (s *gc) GeneratePassword(c *cli.Context) error {
	var passLen = c.Int("length")
	var includeSymbols = c.Bool("symbols")

	s.log().Infof("generating password with length: %d", passLen)
	passwd, err := genPassword(passLen, includeSymbols)
	if err != nil {
		return err
	}

	if !s.confirm("Are you sure you want to save generated password to gopass ('%s')?", s.key) {
		return nil
	}

	s.log().Info("saving password to gopass")
	err = s.gs.setPassword(s.key, passwd)
	if err != nil {
		return err
	}
	return nil
}

// InsertPassword - get ssh-key password from stdin and save it in gopass secret
func (s *gc) InsertPassword(c *cli.Context) error {
	s.log().Info("getting password from stdin")
	data, err := getDataFromStdIn()
	if err != nil {
		return err
	}

	if !s.confirm("Are you sure you want to save imported password to gopass ('%s')?", s.key) {
		return nil
	}

	s.log().Info("saving password to gopass")
	err = s.gs.setPassword(s.key, string(data))
	if err != nil {
		return err
	}

	return nil
}

// DeleteSSHKey - delete ssh-key (private and puplic) from gopass secret
func (s *gc) DeleteSSHKey(c *cli.Context) error {
	var err error

	if !s.confirm("Are you sure you want to DELETE ssh-key (private and public) from gopass ('%s')?", s.key) {
		return nil
	}

	s.log().Info("deleting private ssh-key from gopass")
	err = s.gs.delPrivateSSHKey(s.key)
	if err != nil {
		return err
	}

	s.log().Info("deleting public ssh-key from gopass")
	err = s.gs.delPublicSSHKey(s.key)
	if err != nil {
		return err
	}

	return nil
}

// InsertSSHPrivateKey - get ssh-key private key from stdin and save it in gopass secret
func (s *gc) InsertSSHPrivateKey(c *cli.Context) error {
	s.log().Info("getting private ssh-key from stdin")
	data, err := getDataFromStdIn()
	if err != nil {
		return err
	}

	if !s.confirm("Are you sure you want to save imported private ssh-key to gopass ('%s')?", s.key) {
		return nil
	}

	s.log().Info("saving private ssh-key to gopass")
	err = s.gs.setPrivateSSHKey(s.key, data)
	if err != nil {
		return err
	}

	return nil
}

// ShowSSHPrivateKey - show ssh-key private key
func (s *gc) ShowSSHPrivateKey(c *cli.Context) error {
	var clip = c.Bool("clipboard")

	s.log().Info("getting private ssh-key from gopass")
	privKey, err := s.gs.getPrivateSSHKey(s.key)
	if err != nil {
		return err
	}

	if !clip {
		fmt.Println(string(privKey))
		return nil
	}

	fullKey := s.gs.getPrivateKeyPath(s.key)
	err = s.cb.copy(fullKey, []byte(privKey), 45)
	if err != nil {
		return err
	}

	return nil
}

// DeleteSSHPrivateKey - delete ssh-key private key
func (s *gc) DeleteSSHPrivateKey(c *cli.Context) error {
	var err error

	if !s.confirm("Are you sure you want to DELETE private ssh-key from gopass ('%s')?", s.key) {
		return nil
	}

	s.log().Info("deleting private ssh-key from gopass")
	err = s.gs.delPrivateSSHKey(s.key)
	if err != nil {
		return err
	}
	return nil
}

// InsertSSHPublicKey - get ssh-key public key from stdin and save it in gopass secret
func (s *gc) InsertSSHPublicKey(c *cli.Context) error {
	s.log().Info("getting public ssh-key from stdin")
	data, err := getDataFromStdIn()
	if err != nil {
		return err
	}

	if !s.confirm("Are you sure you want to save imported public ssh-key to gopass ('%s')?", s.key) {
		return nil
	}

	s.log().Info("saving public ssh-key to gopass")
	err = s.gs.setPublicSSHKey(s.key, data)
	if err != nil {
		return err
	}

	return nil
}

// ShowSSHPublicKey - show ssh-key public key
func (s *gc) ShowSSHPublicKey(c *cli.Context) error {
	var clip = c.Bool("clipboard")

	s.log().Info("getting public ssh-key from gopass")
	pubKey, err := s.gs.getPublicSSHKey(s.key)
	if err != nil {
		return err
	}

	pubKey = bytes.SplitN(pubKey, []byte{'\n'}, 2)[0]
	var pubKeySpaceParts = bytes.SplitN(pubKey, []byte{' '}, 3)
	if len(pubKeySpaceParts) == 3 && bytes.Equal(pubKeySpaceParts[2], []byte("noname")) {
		pubKeySpaceParts = pubKeySpaceParts[0:2]
	}

	if len(pubKeySpaceParts) < 3 {
		var comment = getSSHKeyComment(s.key)
		pubKeySpaceParts = append(pubKeySpaceParts, []byte(comment))
		pubKey = bytes.Join(pubKeySpaceParts, []byte{' '})
	}

	var pubKeyStr = string(pubKey)

	if !clip {
		fmt.Println(pubKeyStr)
		return nil
	}

	fullKey := s.gs.getPublicKeyPath(s.key)
	err = s.cb.copy(fullKey, []byte(pubKey), 45)
	if err != nil {
		return err
	}

	return nil
}

// DeleteSSHPublicKey - delete ssh-key public key
func (s *gc) DeleteSSHPublicKey(c *cli.Context) error {
	var err error

	if !s.confirm("Are you sure you want to DELETE public ssh-key from gopass ('%s')?", s.key) {
		return nil
	}

	s.log().Info("deleting public ssh-key from gopass")
	err = s.gs.delPublicSSHKey(s.key)
	if err != nil {
		return err
	}
	return nil
}
