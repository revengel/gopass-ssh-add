package main

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net"
	"os"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

const (
	sshKeyTypeRsa     = "rsa"
	sshKeyTypeEd25519 = "ed25519"
)

type sshAgent struct {
	agent agent.ExtendedAgent
}

func (sa sshAgent) list() (o []string, err error) {
	keys, err := sa.agent.List()
	if err != nil {
		return
	}

	for _, key := range keys {
		o = append(o, key.String())
	}

	return
}

func (sa *sshAgent) add(privateKeyB []byte, password, comment string, lifetime uint32) (err error) {
	var privateKey interface{}

	decodedPem, _ := pem.Decode(privateKeyB)
	keyIsEncrypted := x509.IsEncryptedPEMBlock(decodedPem)

	privateKey, err = sa.decryptPrivateSSHKey(privateKeyB, password, keyIsEncrypted)
	if err != nil {
		return
	}

	key := agent.AddedKey{
		PrivateKey:   privateKey,
		LifetimeSecs: lifetime,
		Comment:      getSSHKeyComment(comment),
	}
	err = sa.agent.Add(key)
	if err != nil {
		return
	}

	return
}

func (sa sshAgent) decryptPrivateSSHKey(data []byte, password string, encrypted bool) (o interface{}, err error) {
	if !encrypted {
		o, err = ssh.ParseRawPrivateKey(data)
		if err != nil {
			if _, ok := err.(*ssh.PassphraseMissingError); ok {
				return sa.decryptPrivateSSHKey(data, password, true)
			}
		}
		return o, err
	}

	if len(password) == 0 {
		return nil, errors.New("private ssh-key is encrypted but provided password is empty")
	}

	return ssh.ParseRawPrivateKeyWithPassphrase(data, []byte(password))
}

func (sa *sshAgent) delete(publicKeyB []byte) (err error) {
	publicKey, _, _, _, err := ssh.ParseAuthorizedKey(publicKeyB)
	if err != nil {
		return
	}

	err = sa.agent.Remove(publicKey)
	if err != nil {
		return
	}
	return
}

func (sa *sshAgent) clear() (err error) {
	err = sa.agent.RemoveAll()
	if err != nil {
		return
	}
	return
}

func newSSHAgent() (sa *sshAgent, err error) {
	sAgent, err := getSSHAgent()
	if err != nil {
		return sa, err
	}

	return &sshAgent{
		agent: sAgent,
	}, nil
}

func getSSHAgent() (sa agent.ExtendedAgent, err error) {
	var sock net.Conn
	sock, err = net.Dial("unix", os.Getenv("SSH_AUTH_SOCK"))
	if err != nil {
		return sa, err
	}

	sa = agent.NewClient(sock)
	return
}
