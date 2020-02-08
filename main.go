package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"
)

var dbs map[string]string
var locks map[string]*sync.Mutex
var encryptionKey = "CrabsAreCool"
var dataLocation = "data"

func main() {
	fmt.Println("CrabDB Started")

	dbs = make(map[string]string)
	locks = make(map[string]*sync.Mutex)
	loadDatabases()
	go bufferWriter()

	r := mux.NewRouter()
	r.HandleFunc("/db/{id}", handleDB)
	r.HandleFunc("/", handleProbe)

	http.ListenAndServe(":8090", r)
}

func loadDatabases() {
	if _, err := os.Stat(dataLocation); os.IsNotExist(err) {
		err = os.MkdirAll(dataLocation, 0755)
		if err != nil {
			panic(err)
		}
	} else {
		err = filepath.Walk(dataLocation, func(path string, info os.FileInfo, err error) error {
			fmt.Println("Path", path)
			dat, err := ioutil.ReadFile(path)
			if err != nil {
				fmt.Println("Failed loading file:", err)
			} else {
				if encryptionKey != "" {
					dat = decrypt([]byte(dat), encryptionKey)
				}

				dbID := strings.Split(path, dataLocation+"/")[1]
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
	err := ioutil.WriteFile(dataLocation+"/"+dbID, outputBytes, 0644)
	if err != nil {
		fmt.Println(err)
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

func deleteEntry(m map[string]interface{}, entries []string) (outMap map[string]interface{}, outErr error) {
	outMap = m

	if len(entries) == 0 {
		outErr = errors.New("No entries to process")
		return
	}

	if entries[0] == "" {
		outErr = errors.New("No entries to process")
		return
	}

	if len(entries) != 1 {
		currentEntry := entries[0]
		subMap := outMap[currentEntry].(map[string]interface{})
		nextEntry := append(entries[:0], entries[0+1:]...)
		subMap, err := deleteEntry(subMap, nextEntry)
		outErr = err
		outMap[currentEntry] = subMap
	} else {
		delete(outMap, entries[0])
	}
	return
}

func handleProbe(w http.ResponseWriter, req *http.Request) {
	fmt.Fprintf(w, "{}")
}

func handleDB(w http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	dbID := vars["id"]

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
			fmt.Fprintf(w, dbs[dbID])
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
					return
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
