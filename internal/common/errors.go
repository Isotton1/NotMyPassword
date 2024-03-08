package common

import "errors"

var ErrNoUserFound error = errors.New("no user found with the provided user name")
var ErrUserExists error = errors.New("user already exists")
var ErrNoAccFound error = errors.New("no account found with the provided account name")
