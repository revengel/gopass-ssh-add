package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math"
	"os"

	"github.com/gopasspw/gopass/pkg/gopass"
	"github.com/manifoldco/promptui"
	"github.com/sethvargo/go-password/password"
)

func getHashFromBytes(in []byte) string {
	h := sha256.New()
	h.Write(in)
	return fmt.Sprintf("%x", h.Sum(nil))
}

func getHash(in string) string {
	return getHashFromBytes([]byte(in))
}

func gopassSecretsDiff(a, b gopass.Byter) bool {
	ahash := getHashFromBytes(a.Bytes())
	bhash := getHashFromBytes(b.Bytes())
	return ahash == bhash
}

func base64Decode(in []byte) (out []byte, err error) {
	var sizeDecoded = base64.StdEncoding.DecodedLen(len(in))
	out = make([]byte, sizeDecoded)
	_, err = base64.StdEncoding.Decode(out, in)
	return
}

func base64Encode(in []byte) (out []byte, err error) {
	var sizeEncoded = base64.StdEncoding.EncodedLen(len(in))
	out = make([]byte, sizeEncoded)
	base64.StdEncoding.Encode(out, in)
	return out, nil
}

func getDataFromStdIn() (out []byte, err error) {
	in := bufio.NewReader(os.Stdin)
	if in.Size() == 0 {
		return nil, errors.New("stdin is empty")
	}

	out, err = io.ReadAll(in)
	if err != nil {
		return
	}
	return
}

func genPassword(length int, symbols bool) (out string, err error) {
	if length < 16 {
		return "", errors.New("password is too short")
	}

	var symbolsNum = int(math.Trunc(float64(length) / 4))
	var digitsNum = int(math.Trunc(float64(length) / 4))

	out, err = password.Generate(length, digitsNum, symbolsNum, true, false)
	if err != nil {
		return
	}
	return
}

func askForConfirmation(s string, ss ...any) bool {
	var err error
	p := promptui.Prompt{
		Label:     fmt.Sprintf(s, ss...),
		IsConfirm: true,
	}

	_, err = p.Run()
	switch err {
	case nil:
		return true
	case promptui.ErrAbort, promptui.ErrInterrupt, promptui.ErrEOF:
		return false
	default:
		panic(err)
	}
}

func getSSHKeyComment(key string) string {
	return fmt.Sprintf("%s:%s", "gssh", key)
}
