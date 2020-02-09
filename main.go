package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/google/logger"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var dbs map[string]string
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
	dbs = make(map[string]string)
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
			dat, err := ioutil.ReadFile(path)
			if err != nil {
				logger.Errorf("Failed loading file: %s", err)
			} else {
				if encryptionKey != "" {
					dat = decrypt([]byte(dat), encryptionKey)
				}

				dbID := strings.Split(path, *dataLocation+"/")[1]
				dbs[dbID] = string(dat)
			}
			return nil
		})

		for k := range dbs {
			locks[k] = &sync.Mutex{}
		}
	}
}

func writeDBToFile(dbID string) {
	locks[dbID].Lock()
	outputBytes := []byte(dbs[dbID])
	if encryptionKey != "" {
		outputBytes = encrypt(outputBytes, encryptionKey)
	}
	err := ioutil.WriteFile(*dataLocation+"/"+dbID, outputBytes, 0644)
	if err != nil {
		logger.Error(err)
	}

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

func applyJSON(o string, i string) (output string, outErr error) {
	var result map[string]interface{}
	err := json.Unmarshal([]byte(o), &result)
	if err != nil {
		outErr = errors.New("Invalid original json")
		return
	}

	var input map[string]interface{}
	err = json.Unmarshal([]byte(i), &input)
	if err != nil {
		outErr = errors.New("Invalid input json")
		return
	}

	for k, v := range input {
		result[k] = v
	}

	outputBytes, err := json.Marshal(result)
	if err != nil {
		outErr = errors.New("Resulting JSON failed to marshal")
		return
	}

	output = string(outputBytes)

	return
}

func deleteEntry(m map[string]interface{}, entries []string) (map[string]interface{}, error) {
	if len(entries) == 0 || entries[0] == "" {
		return nil, errors.New("No entries to process")
	}

	if len(entries) != 1 {
		currentEntry := entries[0]
		if m[currentEntry] == nil {
			return nil, errors.New("not found")
		}
		subMap := m[currentEntry].(map[string]interface{})
		nextEntry := append(entries[:0], entries[0+1:]...)
		subMap, err := deleteEntry(subMap, nextEntry)

		if err != nil {
			return nil, err
		}

		m[currentEntry] = subMap
	} else {
		delete(m, entries[0])
	}

	return m, nil
}

func getEntry(m map[string]interface{}, entries []string) (interface{}, error) {
	if len(entries) == 0 || entries[0] == "" {
		return nil, errors.New("No entries to process")
	}

	if len(entries) != 1 {
		currentEntry := entries[0]
		if m[currentEntry] == nil {
			return nil, errors.New("not found")
		}
		subMap := m[currentEntry].(map[string]interface{})
		nextEntry := append(entries[:0], entries[0+1:]...)
		return getEntry(subMap, nextEntry)
	}

	return m[entries[0]], nil
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
		if dbs[dbID] == "" {
			dbs[dbID] = "{}"
			locks[dbID] = &sync.Mutex{}
		}

		lock := locks[dbID]
		defer lock.Unlock()
		lock.Lock()
		if req.Method == "GET" {
			query, ok := req.URL.Query()["key"]
			if !ok {
				fmt.Fprintf(w, dbs[dbID])
			} else {
				var result map[string]interface{}
				err := json.Unmarshal([]byte(dbs[dbID]), &result)
				if err != nil {
					w.WriteHeader(http.StatusBadRequest)
					fmt.Fprintf(w, err.Error())
				}

				entries := strings.Split(query[0], ".")

				entry, err := getEntry(result, entries)
				if err != nil {
					w.WriteHeader(http.StatusBadRequest)
					fmt.Fprintf(w, err.Error())
				} else {
					outputBytes, err := json.Marshal(entry)
					if err != nil {
						w.WriteHeader(http.StatusBadRequest)
						fmt.Fprintf(w, err.Error())

					} else {
						fmt.Fprintf(w, string(outputBytes))
					}
				}
			}
		} else if req.Method == "PUT" {
			body, err := ioutil.ReadAll(req.Body)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				fmt.Fprintf(w, err.Error())
			} else {
				result, err := applyJSON(dbs[dbID], string(body))
				if err != nil {
					w.WriteHeader(http.StatusBadRequest)
					fmt.Fprintf(w, err.Error())
				} else {
					dbs[dbID] = result
					fmt.Fprintf(w, "OK")
				}
			}
		} else if req.Method == "DELETE" {
			var result map[string]interface{}
			err := json.Unmarshal([]byte(dbs[dbID]), &result)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				fmt.Fprintf(w, err.Error())
			}
			body, err := ioutil.ReadAll(req.Body)
			entries := strings.Split(string(body), ".")

			result, err = deleteEntry(result, entries)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				fmt.Fprintf(w, err.Error())
			} else {
				outputBytes, err := json.Marshal(result)
				if err != nil {
					w.WriteHeader(http.StatusBadRequest)
					fmt.Fprintf(w, err.Error())

				} else {
					dbs[dbID] = string(outputBytes)
					fmt.Fprintf(w, "OK")
				}
			}
		} else {
			w.WriteHeader(http.StatusMethodNotAllowed)
			fmt.Fprintf(w, "Invalid operation")
		}
	}
}

// Got these from: https://www.thepolyglotdeveloper.com/2018/02/encrypt-decrypt-data-golang-application-crypto-packages/
func encrypt(data []byte, passphrase string) []byte {
	block, _ := aes.NewCipher([]byte(createHash(passphrase)))
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext
}

func decrypt(data []byte, passphrase string) []byte {
	key := []byte(createHash(passphrase))
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic(err.Error())
	}
	return plaintext
}

func createHash(key string) string {
	hasher := md5.New()
	hasher.Write([]byte(key))
	return hex.EncodeToString(hasher.Sum(nil))
}
