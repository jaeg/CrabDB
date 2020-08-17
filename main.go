package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/logger"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

var dbs map[string]*DB
var locks map[string]*sync.Mutex
var encryptionKey = "CrabsAreCool"

var certFile = flag.String("cert-file", "", "location of cert file")
var keyFile = flag.String("key-file", "", "location of key file")
var port = flag.String("port", "8090", "port to host on")
var dataLocation = flag.String("data-location", "data", "Data location")
var logPath = flag.String("log-path", "./logs.txt", "Logs location")
var ignoreAuth = flag.Bool("no-auth", false, "No auth enabled")

type User struct {
	Username string
	Password string
	Access   string
}

var users = map[string]User{}

type Session struct {
	lastUsed time.Time
	userName string
}

var sessions map[string]Session

type Credentials struct {
	Password string `json:"password"`
	Username string `json:"username"`
}

func main() {
	flag.Parse()
	lf, err := os.OpenFile(*logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0660)
	if err != nil {
		logger.Fatalf("Failed to open log file: %v", err)
	}
	defer lf.Close()

	defer logger.Init("CrabDB", true, true, lf).Close()

	logger.Info("CrabDB Started")

	sessions = make(map[string]Session)
	dbs = make(map[string]*DB)
	locks = make(map[string]*sync.Mutex)
	go loadConfig()
	loadDatabases()
	go bufferWriter()
	go sessionGroomer()

	r := mux.NewRouter()
	r.HandleFunc("/db/{id}", handleDB)
	r.HandleFunc("/", handleProbe)
	r.HandleFunc("/auth", handleAuth)

	if *certFile == "" || *keyFile == "" {
		logger.Info("Starting http")
		http.ListenAndServe(":"+*port, r)
	} else {
		logger.Info("Starting https")
		http.ListenAndServeTLS(":"+*port, *certFile, *keyFile, r)
	}

}

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

func loadConfig() {
	for {
		cek, err := ioutil.ReadFile("config/encryptionkey")
		if err == nil {
			encryptionKey = string(cek)
		}

		userJSON, err := ioutil.ReadFile("config/users.json")

		if err == nil {
			err := json.Unmarshal([]byte(userJSON), &users)
			if err != nil {
				logger.Error("Failed reading users")
			}
		}
		time.Sleep(5 * time.Second)
	}

}

func loadDatabases() {
	if _, err := os.Stat(*dataLocation); os.IsNotExist(err) {
		err = os.MkdirAll(*dataLocation, 0755)
		if err != nil {
			panic(err)
		}
	} else {
		err = filepath.Walk(*dataLocation, func(path string, info os.FileInfo, err error) error {
			if len(strings.Split(path, *dataLocation+"/")) > 1 {
				dbID := strings.Split(path, *dataLocation+"/")[1]
				dbs[dbID] = LoadDB(path, encryptionKey)
			}

			//This is for the inner function
			return nil
		})

		for k := range dbs {
			locks[k] = &sync.Mutex{}
		}
	}
}

func writeDBToFile(dbID string) {
	locks[dbID].Lock()
	dbs[dbID].Save(*dataLocation+"/"+dbID, encryptionKey)
	locks[dbID].Unlock()
}

func bufferWriter() {
	for {
		//Lock all the DBs
		for k := range locks {
			go writeDBToFile(k)
		}
		time.Sleep(5 * time.Second)
	}
}

func handleProbe(w http.ResponseWriter, req *http.Request) {
	fmt.Fprintf(w, "{}")
}

func handleAuth(w http.ResponseWriter, req *http.Request) {
	if req.Method == "POST" {
		var creds Credentials

		err := json.NewDecoder(req.Body).Decode(&creds)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		expectedUser, ok := users[creds.Username]

		if !ok {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		if expectedUser.Password != creds.Password {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		sessionToken, err := uuid.NewUUID()

		sessions[sessionToken.String()] = Session{userName: creds.Username, lastUsed: time.Now()}

		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
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

func handleDB(w http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	dbID := vars["id"]

	session := req.Header.Get("session")

	_, ok := sessions[session]
	if !ok && !*ignoreAuth {
		w.WriteHeader(http.StatusUnauthorized)
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

	if !accessCheck && !*ignoreAuth {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	//Provide a DB please.
	if dbID == "" {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "No DB Provided")
	} else {

		// If the DB is new create it as an empty json.
		if dbs[dbID] == nil {
			dbs[dbID] = NewDB()
			locks[dbID] = &sync.Mutex{}
		}

		lock := locks[dbID]
		defer lock.Unlock()
		lock.Lock()
		if req.Method == "GET" {
			query, ok := req.URL.Query()["key"]
			if !ok {
				fmt.Fprintf(w, dbs[dbID].Raw)
			} else {
				result, err := dbs[dbID].Get(query[0])
				if err != nil {
					w.WriteHeader(http.StatusBadRequest)
					fmt.Fprintf(w, err.Error())
				} else {
					fmt.Fprintf(w, result)
				}
			}
		} else if req.Method == "PUT" {
			body, err := ioutil.ReadAll(req.Body)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				fmt.Fprintf(w, err.Error())
			} else {
				err := dbs[dbID].Set(string(body))
				if err != nil {
					w.WriteHeader(http.StatusBadRequest)
					fmt.Fprintf(w, err.Error())
				} else {
					fmt.Fprintf(w, "OK")
				}
			}
		} else if req.Method == "DELETE" {
			body, err := ioutil.ReadAll(req.Body)

			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				fmt.Fprintf(w, err.Error())
				return
			}

			err = dbs[dbID].Delete(string(body))
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				fmt.Fprintf(w, err.Error())
			} else {
				fmt.Fprintf(w, "OK")
			}
		} else {
			w.WriteHeader(http.StatusMethodNotAllowed)
			fmt.Fprintf(w, "Invalid operation")
		}
	}
}
