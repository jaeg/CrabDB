package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/google/logger"
	"github.com/gorilla/mux"
	"github.com/jaeg/CrabDB/db"
	"github.com/jaeg/CrabDB/token"
)

const jwtKey = "12345678910111213141516171819202122232425262728293032"
const userDBDPath = "mgr/users"
const userConfigPath = "config/users.json"

//User represents a user of the database.
type User struct {
	Username string
	Password string
	Access   string
}

type BasicAuthMiddleware struct {
	tokenFactory token.TokenFactory
	userDB       *db.DB
}

func NewBasicAuthMiddleware() (*BasicAuthMiddleware, error) {
	b := &BasicAuthMiddleware{}

	//Check to see if the user DB exists
	userDB := db.LoadDB(userDBDPath, db.EncryptionKey, "users")

	//If there's no data in the DB set it up.
	if len(userDB.Raw) == 0 {
		userDB = db.NewDB("users")
		logger.Info("User database not setup, initializing")
		userJSONBytes, err := ioutil.ReadFile(userConfigPath)
		if err != nil {
			return nil, err
		}

		userJSON := string(userJSONBytes)
		err = userDB.Set(userJSON)
		if err != nil {
			logger.Errorf("Error applying user json %s", err.Error())
		}

		userDB.Save(userDBDPath, db.EncryptionKey)
		logger.Info("User database is now setup")
	}

	b.userDB = userDB

	factory, err := token.NewJWTTokenFactory(jwtKey)
	if err != nil {
		logger.Error("Failed to create jwt factory")
		logger.Error(err)
		return nil, err
	}

	b.tokenFactory = factory

	return b, nil
}

func (b *BasicAuthMiddleware) HandleAuth(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		username, password, ok := r.BasicAuth()
		if !ok {
			http.Error(w, "No basic auth credentials provided", http.StatusUnauthorized)
			return
		}

		expectedUser, err := b.getUser(username)
		if err != nil {
			w.Header().Set("WWW-Authenticate", `Basic realm="restricted", charset="UTF-8"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			logger.Error(err)
			return
		}

		if expectedUser.Password != password {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		token, err := b.tokenFactory.CreateToken(username, time.Hour)
		if err != nil {
			logger.Error("Failed to create jwt token")
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			logger.Error(err)
			return
		}

		w.Header().Set("token", "Bearer "+token)

	} else {
		w.WriteHeader(http.StatusMethodNotAllowed)
		fmt.Fprintf(w, "Invalid operation")
	}
}

func (b *BasicAuthMiddleware) Auth(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		vars := mux.Vars(r)
		dbID := vars["id"]

		authHeader := strings.Split(r.Header.Get("Authorization"), "Bearer ")

		//Bearer token validation
		if len(authHeader) != 2 {
			w.Header().Set("WWW-Authenticate", `Basic realm="restricted", charset="UTF-8"`)
			http.Error(w, "No bearer token", http.StatusUnauthorized)
			return
		}

		jwtToken := authHeader[1]

		payload, err := b.tokenFactory.VerifyToken(jwtToken)

		if err != nil {
			w.Header().Set("WWW-Authenticate", `Basic realm="restricted", charset="UTF-8"`)
			http.Error(w, "Unauthorized 1", http.StatusUnauthorized)
			return
		}

		user, err := b.getUser(payload.Username)
		if err != nil {
			w.Header().Set("WWW-Authenticate", `Basic realm="restricted", charset="UTF-8"`)
			http.Error(w, "Unauthorized 1", http.StatusUnauthorized)
			logger.Error(err)
			return
		}
		availableDBs := strings.Split(user.Access, ",")

		accessCheck := false
		for _, v := range availableDBs {
			if dbID == v {
				accessCheck = true
			}
		}

		if !accessCheck {
			w.Header().Set("WWW-Authenticate", `Basic realm="restricted", charset="UTF-8"`)
			http.Error(w, "Unauthorized DB", http.StatusUnauthorized)
			return
		}

		//Success
		next.ServeHTTP(w, r)
	})
}

var ErrNoUser = errors.New("no user")

// Wraps what it takes to get the user from the database.
func (b *BasicAuthMiddleware) getUser(username string) (*User, error) {
	userJSON, err := b.userDB.Get(username)
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
