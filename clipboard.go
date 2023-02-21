package main

import (
	"context"

	"github.com/gopasspw/gopass/pkg/clipboard"
)

type clp struct {
	ctx context.Context
}

func (c *clp) copy(name string, content []byte, timeout int) (err error) {
	err = clipboard.CopyTo(c.ctx, name, content, timeout)
	if err != nil {
		return
	}
	return
}

func newClipboard(ctx context.Context) (c *clp, err error) {
	return &clp{
		ctx: ctx,
	}, nil
}
