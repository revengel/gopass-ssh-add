package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/ScaleFT/sshkeys"
	"golang.org/x/crypto/ssh"
)

func sshKeygen(ttype, password string, bits int) (privKey, pubKey []byte, err error) {
	switch ttype {
	case "rsa":
		privKey, pubKey, err = sshKeygenRsa(bits, password)
	case "ed25519":
		privKey, pubKey, err = sshKeygenEd25519(password)
	default:
		return nil, nil, fmt.Errorf("ssh-keygen invalid ssh-key type '%s'", ttype)
	}

	if err != nil {
		return
	}

	return
}

func sshKeygenRsa(bitSize int, password string) (privBytes, pubBytes []byte, err error) {
	privkey, err := rsa.GenerateKey(rand.Reader, bitSize)
	if err != nil {
		return nil, nil, err
	}

	err = privkey.Validate()
	if err != nil {
		return nil, nil, err
	}

	var privateKeyPEM *pem.Block

	privateKeyPEM = &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privkey),
	}

	privatePEM := pem.EncodeToMemory(privateKeyPEM)

	pub, err := ssh.NewPublicKey(&privkey.PublicKey)
	if err != nil {
		return nil, nil, err
	}

	pubB := ssh.MarshalAuthorizedKey(pub)

	if password == "" {
		return privatePEM, pubB, nil
	}

	privateKeyPEM, err = x509.EncryptPEMBlock(rand.Reader,
		privateKeyPEM.Type, privateKeyPEM.Bytes, []byte(password),
		x509.PEMCipherAES256)
	if err != nil {
		return nil, nil, err
	}

	privatePEM = pem.EncodeToMemory(privateKeyPEM)

	return privatePEM, pubB, nil
}

func sshKeygenEd25519(password string) (privBytes, pubBytes []byte, err error) {
	pubkey, privkey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	privBytes, err = sshkeys.Marshal(privkey, &sshkeys.MarshalOptions{
		Passphrase: []byte(password),
		Format:     sshkeys.FormatOpenSSHv1,
	})
	if err != nil {
		return nil, nil, err
	}

	pub, err := ssh.NewPublicKey(pubkey)
	if err != nil {
		return nil, nil, err
	}

	pubBytes = ssh.MarshalAuthorizedKey(pub)

	return
}
