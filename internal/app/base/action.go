package base

import "context"

type Action[T any, R any] interface {
	Execute(ctx context.Context, in *T) (*R, error)
}

type Void struct{}
