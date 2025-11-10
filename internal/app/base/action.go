package base

type Action[T any, R any] interface {
	Execute(in *T) (*R, error)
}

type Void struct{}
