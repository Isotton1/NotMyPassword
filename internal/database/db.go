package database

import (
	"database/sql"

	"github.com/Isotton1/NotMyPassword/internal/common"
	"github.com/Isotton1/NotMyPassword/internal/models"

	_ "modernc.org/sqlite"
)

var Db *sql.DB

func InitDB(url string) error {
	var err error
	Db, err = sql.Open("sqlite", url)
	if err != nil {
		return err
	}

	usersTable := `
	CREATE TABLE IF NOT EXISTS Users (
		user_id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT NOT NULL UNIQUE,
		master_password_hash TEXT NOT NULL,
		salt TEXT NOT NULL,
		pepper TEXT NOT NULL
	);`
	passwordsTable := `
	CREATE TABLE IF NOT EXISTS Passwords (
		password_id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER NOT NULL,
		account TEXT NOT NULL UNIQUE,
		password TEXT NOT NULL,
		FOREIGN KEY (user_id) REFERENCES Users(user_id)
	);`

	_, err = Db.Exec(usersTable)
	if err != nil {
		return err
	}
	_, err = Db.Exec(passwordsTable)
	if err != nil {
		return err
	}

	return nil
}

func InsertUser(user *models.User) error {
	exist, err := HasUser(user.Username)
	if err != nil {
		return err
	}
	if exist {
		return common.ErrUserExists
	}
	query := `INSERT INTO Users(username, master_password_hash, salt, pepper) VALUES(?, ?, ?, ?)`
	_, err = Db.Exec(query, user.Username, user.PasswordHash, user.Salt, user.Pepper)
	if err != nil {
		return err
	}
	return nil
}

func InsertPassword(password *models.Password) error {
	exist, err := HasUser(password.Account)
	if err != nil {
		return err
	}
	if exist {
		query := `UPDATE Passwords SET account = ?, password = ? WHERE user_id = ?`
		_, err = Db.Exec(query, password.Account, password.Password, password.UserID)
		if err != nil {
			return err
		}
		return nil
	}
	query := `INSERT INTO Passwords(user_id, account, password) VALUES(?, ?, ?)`
	_, err = Db.Exec(query, password.UserID, password.Account, password.Password)
	if err != nil {
		return err
	}
	return nil
}

func GetUser(username string) (models.User, error) {
	var userID int
	var masterHash, salt, pepper string
	err := Db.QueryRow("SELECT user_id, master_password_hash, salt, pepper FROM users WHERE username = ?", username).Scan(&userID, &masterHash, &salt, &pepper)
	if err != nil {
		if err == sql.ErrNoRows {
			return models.User{}, common.ErrNoUserFound
		}
		return models.User{}, err
	}
	user := models.User{
		ID:           userID,
		Username:     username,
		PasswordHash: masterHash,
		Salt:         salt,
		Pepper:       pepper,
	}
	return user, nil
}

func GetPassword(userID int, account string) (models.Password, error) {
	var password string
	err := Db.QueryRow("SELECT password FROM Passwords WHERE account = ? AND user_id = ?", account, userID).Scan(&password)
	if err != nil {
		if err == sql.ErrNoRows {
			return models.Password{}, common.ErrNoAccFound
		}
		return models.Password{}, err
	}
	passwordStruct := models.Password{
		UserID:   userID,
		Account:  account,
		Password: password,
	}
	return passwordStruct, nil
}

func HasUser(username string) (bool, error) {
	var exist bool
	err := Db.QueryRow("SELECT EXISTS(SELECT 1 FROM Users WHERE username = ?)", username).Scan(&exist)
	if err != nil && err != sql.ErrNoRows {
		return false, err
	}

	return exist, nil
}

func HasPassword(userID string) (bool, error) {
	var exist bool
	err := Db.QueryRow("SELECT EXISTS(SELECT 1 FROM Passwords WHERE user_id = ?)", userID).Scan(&exist)
	if err != nil && err != sql.ErrNoRows {
		return false, err
	}

	return exist, nil
}
