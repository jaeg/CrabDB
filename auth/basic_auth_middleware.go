package auth

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/google/logger"
	"github.com/gorilla/mux"
	"github.com/jaeg/CrabDB/token"
)

const jwtKey = "12345678910111213141516171819202122232425262728293032"

//User represents a user of the database.
type User struct {
	Username string
	Password string
	Access   string
}

type BasicAuthMiddleware struct {
	users        map[string]User
	tokenFactory token.TokenFactory
}

func NewBasicAuthMiddleware() (*BasicAuthMiddleware, error) {
	b := &BasicAuthMiddleware{}
	userJSON, err := ioutil.ReadFile("config/users.json")

	var users map[string]User
	if err == nil {
		err := json.Unmarshal([]byte(userJSON), &users)
		if err != nil {
			logger.Error("Failed reading users")
		}
	}

	b.users = users

	factory, err := token.NewJWTTokenFactory(jwtKey)
	if err != nil {
		logger.Error("Failed to create jwt maker")
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

		//This is temporary and a very bad solution currently.
		// I want these stored in the DB itself.
		expectedUser, ok := b.users[username]

		if !ok {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
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

		http.SetCookie(w, &http.Cookie{
			Name:    "session_token",
			Value:   token,
			Expires: time.Now().Add(120 * time.Second),
		})

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

		availableDBs := strings.Split(b.users[payload.Username].Access, ",")

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
