package models

type User struct {
	ID           int    `db:"user_id"`
	Username     string `db:"username"`
	PasswordHash string `db:"password_hash"`
	Salt         string `db:"salt"`
	Pepper       string `db:"Pepper"`
}

type Password struct {
	UserID   int    `db:"user_id"`
	Account  string `db:"account"`
	Password string `db:"password"`
}
