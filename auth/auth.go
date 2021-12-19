package auth

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/google/logger"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

//User represents a user of the database.
type User struct {
	Username string
	Password string
	Access   string
}

var users = map[string]User{}

//Session represents a user's session after login
type Session struct {
	lastUsed time.Time
	userName string
}

var sessions map[string]Session

//Credentials represents a set of credentials for a login request.
type Credentials struct {
	Password string `json:"password"`
	Username string `json:"username"`
}

func Init() {
	sessions = make(map[string]Session)
	userJSON, err := ioutil.ReadFile("config/users.json")

	if err == nil {
		err := json.Unmarshal([]byte(userJSON), &users)
		if err != nil {
			logger.Error("Failed reading users")
		}
	}

	go sessionGroomer()
}

func HandleAuth(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		var creds Credentials

		err := json.NewDecoder(r.Body).Decode(&creds)
		if err != nil {
			http.Error(w, "Unauthorized 1", http.StatusUnauthorized)
			return
		}

		expectedUser, ok := users[creds.Username]

		if !ok {
			http.Error(w, "Unauthorized 2", http.StatusUnauthorized)
			return
		}

		if expectedUser.Password != creds.Password {
			http.Error(w, "Unauthorized 3", http.StatusUnauthorized)
			return
		}

		sessionToken, err := uuid.NewUUID()

		sessions[sessionToken.String()] = Session{userName: creds.Username, lastUsed: time.Now()}
		fmt.Println(sessions)
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			logger.Error(err)
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:    "session_token",
			Value:   sessionToken.String(),
			Expires: time.Now().Add(120 * time.Second),
		})

	} else {
		w.WriteHeader(http.StatusMethodNotAllowed)
		fmt.Fprintf(w, "Invalid operation")
	}
}
func BasicAuth(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		vars := mux.Vars(r)
		dbID := vars["id"]

		session := r.Header.Get("session")

		_, ok := sessions[session]
		fmt.Println(sessions)
		if !ok {
			w.Header().Set("WWW-Authenticate", `Basic realm="restricted", charset="UTF-8"`)
			http.Error(w, "Unauthorized 1", http.StatusUnauthorized)
			return
		}

		sessionStruct := sessions[session]
		sessionStruct.lastUsed = time.Now()
		sessions[session] = sessionStruct
		availableDBs := strings.Split(users[sessionStruct.userName].Access, ",")

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
		return
	})
}

//Grooms the active sessions using the DB
func sessionGroomer() {
	for {
		for k, v := range sessions {
			if time.Since(v.lastUsed).Seconds() > 120 {
				logger.Infof("Remove session: %s", k)
				delete(sessions, k)
			}
		}
		time.Sleep(time.Second * 1)
	}
}
