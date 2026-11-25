// Package clierr carries the exit code together with the error.
package clierr

import (
	"errors"
	"fmt"
)

const (
	General   = 1
	Usage     = 2
	Auth      = 3
	NotFound  = 4
	RateLimit = 5
)

type Error struct {
	Code int
	Msg  string
}

func (e *Error) Error() string { return e.Msg }

func New(code int, format string, a ...any) *Error {
	return &Error{Code: code, Msg: fmt.Sprintf(format, a...)}
}

func ExitCode(err error) int {
	if err == nil {
		return 0
	}
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return General
}
