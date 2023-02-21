package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSSHKeygenRsaWoPassword(t *testing.T) {
	privBytes, pubBytes, err := sshKeygenRsa(2048, "")
	assert.Nil(t, err)

	agent, err := newSSHAgent()
	assert.Nil(t, err)

	err = agent.add(privBytes, "", "test ssh key", 30)
	assert.Nil(t, err)

	err = agent.delete(pubBytes)
	assert.Nil(t, err)
}

func TestSSHKeygenRsa(t *testing.T) {
	passwd, err := genPassword(32, true)
	assert.Nil(t, err)

	privBytes, pubBytes, err := sshKeygenRsa(2048, passwd)
	assert.Nil(t, err)

	agent, err := newSSHAgent()
	assert.Nil(t, err)

	err = agent.add(privBytes, passwd, "test ssh key", 30)
	assert.Nil(t, err)

	err = agent.delete(pubBytes)
	assert.Nil(t, err)
}

func TestSSHKeygenEd25519WoPassword(t *testing.T) {
	privBytes, pubBytes, err := sshKeygenEd25519("")
	assert.Nil(t, err)

	agent, err := newSSHAgent()
	assert.Nil(t, err)

	err = agent.add(privBytes, "", "test ssh key", 30)
	assert.Nil(t, err)

	err = agent.delete(pubBytes)
	assert.Nil(t, err)
}

func TestSSHKeygenEd25519(t *testing.T) {
	passwd, err := genPassword(32, true)
	assert.Nil(t, err)

	privBytes, pubBytes, err := sshKeygenEd25519(passwd)
	assert.Nil(t, err)

	agent, err := newSSHAgent()
	assert.Nil(t, err)

	err = agent.add(privBytes, passwd, "test ssh key", 30)
	assert.Nil(t, err)

	err = agent.delete(pubBytes)
	assert.Nil(t, err)
}
