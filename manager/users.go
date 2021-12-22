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
	Admin    bool
	Enabled  bool
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

	user := User{Username: "test", Access: "1,2,3,4", Enabled: true}
	CreateUser(user)

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

	if userJSON == "null" {
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

func UpdateUser(user User) {
	if userDB == nil {
		LoadUserDatabase()
	}
	u, err := userDB.Get(user.Username)

	if err == nil {
		if u != "null" {
			newUser := make(map[string]interface{})
			newUser[user.Username] = user
			userJSON, err := json.Marshal(newUser)
			if err != nil {
				logger.Errorf("Error updating user %s", err.Error())
			}

			err = userDB.Set(string(userJSON))
			if err != nil {
				logger.Errorf("Error creating user %s", err.Error())
			}
			userDB.Save(userDBDPath, db.EncryptionKey)
		}
	} else {
		logger.Error(err)
	}
}

func CreateUser(user User) {
	if userDB == nil {
		LoadUserDatabase()
	}
	u, err := userDB.Get(user.Username)

	if err == nil {
		if u == "null" {
			newUser := make(map[string]interface{})
			newUser[user.Username] = user
			userJSON, err := json.Marshal(newUser)
			if err != nil {
				logger.Errorf("Error updating user %s", err.Error())
			}

			err = userDB.Set(string(userJSON))
			if err != nil {
				logger.Errorf("Error creating user %s", err.Error())
			}
			userDB.Save(userDBDPath, db.EncryptionKey)
		}
	} else {
		logger.Error(err)
	}
}

func DeleteUser(user string) {
	if userDB == nil {
		LoadUserDatabase()
	}

	if user == "" {
		logger.Errorf("No user provided to delete")
	}

	err := userDB.Delete(user)

	if err != nil {
		logger.Errorf("Error deleting user %s", err.Error())
	}

	userDB.Save(userDBDPath, db.EncryptionKey)
}
