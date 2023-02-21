package main

import (
	"context"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/gopasspw/gopass/pkg/gopass"
	"github.com/gopasspw/gopass/pkg/gopass/api"
	"github.com/gopasspw/gopass/pkg/gopass/secrets"
)

const (
	gopassKeySuffixPassword   = "password"
	gopassKeySuffixPrivateKey = "ssh-key"
	gopassKeySuffixPublicKey  = "ssh-key.pub"
)

var (
	// ErrNotFound is returned if an entry was not found.
	ErrNotFound = fmt.Errorf("entry is not in the password store")
)

type gopassStorage struct {
	ctx context.Context
	api *api.Gopass
}

// Close -
func (gs *gopassStorage) Close() error {
	return gs.api.Close(gs.ctx)
}

// get list of ssh key paths
func (gs gopassStorage) list(prefix string) (ll []string, err error) {
	var keys []string
	var m = make(map[string]bool)

	keys, err = gs.api.List(gs.ctx)
	if err != nil {
		return
	}

	re := regexp.MustCompile(`^` + prefix + `/`)
	for _, key := range keys {
		if !re.MatchString(key) {
			continue
		}
		var dirPath = filepath.Dir(key)
		dirPath = strings.TrimPrefix(dirPath, fmt.Sprintf("%s/", prefix))

		if _, ok := m[dirPath]; !ok {
			ll = append(ll, dirPath)
			m[dirPath] = true
		}
	}

	return
}

// getting path
func (gs gopassStorage) getPath(key, suffix string) string {
	return filepath.Join(key, suffix)
}

func (gs gopassStorage) getPasswordPath(key string) string {
	return gs.getPath(key, gopassKeySuffixPassword)
}

func (gs gopassStorage) getPrivateKeyPath(key string) string {
	return gs.getPath(key, gopassKeySuffixPrivateKey)
}

func (gs gopassStorage) getPublicKeyPath(key string) string {
	return gs.getPath(key, gopassKeySuffixPublicKey)
}

func (gs *gopassStorage) getSecret(key string) (s gopass.Secret, err error) {
	return gs.api.Get(gs.ctx, key, "latest")
}

func (gs *gopassStorage) setSecret(key string, s gopass.Secret) (err error) {
	var secretNotFound bool
	es, err := gs.getSecret(key)
	if err != nil {
		secretNotFound = err.Error() == ErrNotFound.Error()
		if !secretNotFound {
			return
		}
	}

	if !secretNotFound && gopassSecretsDiff(es, s) {
		return nil
	}

	return gs.api.Set(gs.ctx, key, s)
}

func (gs *gopassStorage) delSecret(key string) (err error) {
	err = gs.api.Remove(gs.ctx, key)
	if err != nil && err.Error() != ErrNotFound.Error() {
		return
	}
	return nil
}

func (gs gopassStorage) getPassword(key string) (p string, err error) {
	k := gs.getPasswordPath(key)
	s, err := gs.getSecret(k)
	if err != nil {
		if err.Error() != ErrNotFound.Error() {
			return "", nil
		}
		return
	}
	return s.Password(), nil
}

func (gs *gopassStorage) setPassword(key, password string) (err error) {
	k := gs.getPasswordPath(key)
	var s = secrets.NewAKV()
	s.SetPassword(password)
	return gs.setSecret(k, s)
}

func (gs *gopassStorage) delPassword(key string) (err error) {
	k := gs.getPasswordPath(key)
	return gs.delSecret(k)
}

func (gs gopassStorage) getSSHKey(key string) (o []byte, err error) {
	s, err := gs.getSecret(key)
	if err != nil {
		return
	}

	return base64Decode([]byte(s.Body()))
}

func (gs gopassStorage) setSSHKey(key, filename string, data []byte) (err error) {
	var s = secrets.NewAKV()
	err = s.Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))
	if err != nil {
		return
	}

	err = s.Set("Content-Transfer-Encoding", "Base64")
	if err != nil {
		return
	}

	encoded, err := base64Encode(data)
	if err != nil {
		return
	}

	_, err = s.Write(encoded)
	if err != nil {
		return
	}

	return gs.setSecret(key, s)
}

func (gs gopassStorage) getPrivateSSHKey(key string) (o []byte, err error) {
	k := gs.getPrivateKeyPath(key)
	return gs.getSSHKey(k)
}

func (gs gopassStorage) getPublicSSHKey(key string) (o []byte, err error) {
	k := gs.getPublicKeyPath(key)
	return gs.getSSHKey(k)
}

func (gs gopassStorage) setPrivateSSHKey(key string, data []byte) (err error) {
	k := gs.getPrivateKeyPath(key)
	return gs.setSSHKey(k, gopassKeySuffixPrivateKey, data)
}

func (gs gopassStorage) setPublicSSHKey(key string, data []byte) (err error) {
	k := gs.getPublicKeyPath(key)
	return gs.setSSHKey(k, gopassKeySuffixPublicKey, data)
}

func (gs *gopassStorage) delPrivateSSHKey(key string) (err error) {
	k := gs.getPrivateKeyPath(key)
	return gs.delSecret(k)
}

func (gs *gopassStorage) delPublicSSHKey(key string) (err error) {
	k := gs.getPublicKeyPath(key)
	return gs.delSecret(k)
}

func newGopassStorage(ctx context.Context) (g *gopassStorage, err error) {
	gp, err := api.New(ctx)
	if err != nil {
		return
	}

	return &gopassStorage{
		ctx: ctx,
		api: gp,
	}, nil
}
