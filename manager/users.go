package manager

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"os"

	"github.com/google/logger"
	"github.com/jaeg/CrabDB/db"
)

//User represents a user of the database.
type User struct {
	Username string
	Password string
	Access   string
}

const userDBDPath = "mgr/users"
const userConfigPath = "config/users.json"

var userDB *db.DB

func LoadUserDatabase() error {
	//Check to see if the user DB exists
	userDB = db.LoadDB(userDBDPath, db.EncryptionKey, "users")

	//If there's no data in the DB set it up.
	if len(userDB.Raw) == 0 {
		userDB = db.NewDB("users")
		logger.Info("User database not setup, initializing")
		if _, err := os.Stat(userConfigPath); os.IsNotExist(err) {
			logger.Error("No initial user config present")
		} else {
			userJSONBytes, err := ioutil.ReadFile(userConfigPath)
			if err != nil {
				return err
			}

			userJSON := string(userJSONBytes)
			err = userDB.Set(userJSON)
			if err != nil {
				logger.Errorf("Error applying user json %s", err.Error())
			}
		}

		userDB.Save(userDBDPath, db.EncryptionKey)
		logger.Info("User database is now setup")
	}
	return nil
}

var ErrNoUser = errors.New("no user")

func GetUser(username string) (*User, error) {
	if userDB == nil {
		LoadUserDatabase()
	}

	userJSON, err := userDB.Get(username)
	if err != nil {
		return nil, err
	}

	if userJSON == "" {
		return nil, ErrNoUser
	}

	//Get the user to look at their info.
	var user User
	err = json.Unmarshal([]byte(userJSON), &user)
	if err != nil {
		return nil, err
	}

	return &user, nil
}
