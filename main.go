package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"syscall"

	"github.com/Isotton1/NotMyPassword/internal/common"
	"github.com/Isotton1/NotMyPassword/internal/crypto"
	"github.com/Isotton1/NotMyPassword/internal/database"
	"github.com/Isotton1/NotMyPassword/internal/models"

	"golang.org/x/term"
)

func main() {
	argv := os.Args
	argc := len(argv)

	if argc < 2 {
		log.Fatal("This Program Needs Arguments!\n For help: NotMyPassword -h")
	}

	dbPath := "database.db"
	if _, err := os.Stat(dbPath); errors.Is(err, os.ErrNotExist) {
		dbFile, err := os.Create(dbPath)
		if err != nil {
			log.Panic(err)
		}
		dbFile.Close()
	}
	err := database.InitDB(dbPath)
	if err != nil {
		log.Fatal(err)
	}

	switch argv[1] {
	case "-h":
		usage()
	case "-nu":
		fmt.Println("Enter a New Master Password: ")
		masterPassword, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			log.Panic(err)
		}
		username := argv[2]
		err = createNewUser(username, string(masterPassword))
		if err != nil {
			if err == common.ErrUserExists {
				log.Fatal(err)
			}
			log.Panic(err)
		}
	case "-na":
		fmt.Println("Enter the Master Password: ")
		masterPassword, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			log.Panic(err)
		}
		username := argv[2]
		user, err := database.GetUser(username)
		if err != nil {
			log.Panic(err)
		}
		if !verifyMaster(user, string(masterPassword)) {
			log.Fatal("Wrong password")
		}
		fmt.Println("Enter a New Password for the Account: ")
		newPassword, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			log.Panic(err)
		}
		account := argv[3]
		err = createNewAcc(user, account, masterPassword, newPassword)
		if err != nil {
			if err == common.ErrNoUserFound {
				log.Fatal(err)
			}
			log.Panic(err)
		}
	default:
		fmt.Println("Enter the password: ")
		password, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			log.Panic(err)
		}
		username := argv[1]
		user, err := database.GetUser(username)
		if err != nil {
			log.Panic(err)
		}
		if !verifyMaster(user, string(password)) {
			log.Fatal("Wrong password")
		}
		account := argv[2]
		accPasswordStruct, err := database.GetPassword(user.ID, account)
		if err != nil {
			if err == common.ErrNoAccFound {
				log.Fatal(err)
			}
			log.Panic(err)
		}
		accPassword, err := crypto.Decrypt(accPasswordStruct.Password, password)
		if err != nil {
			log.Panic("Error during Decrypt(): " + err.Error())
		}
		fmt.Println(accPassword)
	}
}

func createNewUser(username string, master string) error {
	salt, err := crypto.GenerateRandomString(128)
	if err != nil {
		return err
	}
	pepper, err := crypto.GenerateRandomString(128)
	if err != nil {
		return err
	}
	masterHash := crypto.NewHash(salt + master + pepper)
	user := models.User{
		Username:     username,
		PasswordHash: masterHash,
		Salt:         salt,
		Pepper:       pepper,
	}
	err = database.InsertUser(&user)
	if err != nil {
		return err
	}
	return nil
}
func createNewAcc(user models.User, account string, master, password []byte) error {
	encryptedPassword, err := crypto.Encrypt(password, master)
	if err != nil {
		return err
	}

	passwordStruct := models.Password{
		UserID:   user.ID,
		Account:  account,
		Password: encryptedPassword,
	}

	err = database.InsertPassword(&passwordStruct)
	if err != nil {
		return err
	}
	return nil
}

func usage() {
	fmt.Print("Usages:\n" +
		"Access Password: NotMyPassword <User Name> <Account Name>\n" +
		"Create New User: NotMyPassword -nu <User Name>\n" +
		"Create New Account: NotMyPassword -na <User Name> <Account Name>\n")
}

func verifyMaster(user models.User, password string) bool {
	masterHash := user.PasswordHash
	salt := user.Salt
	pepper := user.Pepper
	passwordHash := crypto.NewHash(salt + password + pepper)
	return passwordHash == masterHash
}
