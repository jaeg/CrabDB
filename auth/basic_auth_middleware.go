package auth

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/logger"
	"github.com/gorilla/mux"
	"github.com/jaeg/CrabDB/manager"
	"github.com/jaeg/CrabDB/token"
)

const jwtKey = "12345678910111213141516171819202122232425262728293032"

type BasicAuthMiddleware struct {
	tokenFactory token.TokenFactory
}

func NewBasicAuthMiddleware() (*BasicAuthMiddleware, error) {
	b := &BasicAuthMiddleware{}

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

		expectedUser, err := manager.GetUser(username)
		if err != nil {
			w.Header().Set("WWW-Authenticate", `Basic realm="restricted", charset="UTF-8"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			logger.Error(err)
			return
		}

		if expectedUser == nil {
			w.Header().Set("WWW-Authenticate", `Basic realm="restricted", charset="UTF-8"`)
			http.Error(w, "Unauthorized 1", http.StatusUnauthorized)
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
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		user, err := manager.GetUser(payload.Username)
		if err != nil {
			w.Header().Set("WWW-Authenticate", `Basic realm="restricted", charset="UTF-8"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			logger.Error(err)
			return
		}

		if user == nil {
			w.Header().Set("WWW-Authenticate", `Basic realm="restricted", charset="UTF-8"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			logger.Error(err)
			return
		}

		if !user.Enabled {
			w.Header().Set("WWW-Authenticate", `Basic realm="restricted", charset="UTF-8"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
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
