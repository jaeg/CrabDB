package main

import (
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
	"github.com/gorilla/mux"
	"github.com/jaeg/CrabDB/auth"
	"github.com/jaeg/CrabDB/db"
	"github.com/jaeg/CrabDB/journal"
	"github.com/jaeg/CrabDB/journalplayback"
)

var dbs map[string]*db.DB
var locks map[string]*sync.Mutex

var certFile = flag.String("cert-file", "", "location of cert file")
var keyFile = flag.String("key-file", "", "location of key file")
var port = flag.String("port", "8090", "port to host on")
var dataLocation = flag.String("data-location", "data", "Data location")
var logLocation = flag.String("log-location", "logs", "Logs location")
var logPath = flag.String("log-path", "./logs.txt", "Logs location")

func main() {
	flag.Parse()
	lf, err := os.OpenFile(*logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0660)
	if err != nil {
		logger.Fatalf("Failed to open log file: %v", err)
	}
	defer lf.Close()

	defer logger.Init("CrabDB", true, true, lf).Close()

	logger.Info("CrabDB Started")
	journal.LogLocation = *logLocation

	dbs = make(map[string]*db.DB)
	locks = make(map[string]*sync.Mutex)

	//Pick the middleware to use for authentication
	mw, err := auth.NewBasicAuthMiddleware()
	if err != nil {
		panic(err)
	}
	auth.UseMiddleware(mw)

	loadConfig()

	ldbs := journalplayback.PlayLogs(*logLocation + "/logfile.txt")
	loadDatabases()

	go configWatcher()
	go bufferWriter()

	//Verify DB with playback
	for k, v := range dbs {
		if ldbs[k] == nil {
			logger.Error("DB missing from logs: ", k)
			return
		}

		if v.Raw != ldbs[k].Raw {
			logger.Error("Data mismatch")
			return
		}
	}

	r := mux.NewRouter()
	r.HandleFunc("/db/{id}", auth.Auth(handleDB))
	r.HandleFunc("/", handleProbe)
	r.HandleFunc("/auth", auth.HandleAuth)

	if *certFile == "" || *keyFile == "" {
		logger.Info("Starting http")
		http.ListenAndServe(":"+*port, r)
	} else {
		logger.Info("Starting https")
		http.ListenAndServeTLS(":"+*port, *certFile, *keyFile, r)
	}

}

func loadConfig() {
	if _, err := os.Stat(*logLocation); os.IsNotExist(err) {
		err = os.MkdirAll(*logLocation, 0755)
		if err != nil {
			panic(err)
		}
	}

	cek, err := ioutil.ReadFile("config/encryptionkey")
	if err == nil {
		db.EncryptionKey = string(cek)
	}
}

// Watches the configuration file and reloads as necessary.
func configWatcher() {
	if _, err := os.Stat(*logLocation); os.IsNotExist(err) {
		err = os.MkdirAll(*logLocation, 0755)
		if err != nil {
			panic(err)
		}
	}

	for {
		loadConfig()
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
				dbs[dbID] = db.LoadDB(path, db.EncryptionKey, dbID)
			}

			//This is for the inner function
			return nil
		})

		if err != nil {
			panic(err)
		}

		for k := range dbs {
			locks[k] = &sync.Mutex{}
		}
	}
}

func writeDBToFile(dbID string) {
	locks[dbID].Lock()
	dbs[dbID].Save(*dataLocation+"/"+dbID, db.EncryptionKey)
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

func handleDB(w http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	dbID := vars["id"]

	//Provide a DB please.
	if dbID == "" {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "No DB Provided")
	} else {

		// If the DB is new create it as an empty json.
		if dbs[dbID] == nil {
			dbs[dbID] = db.NewDB(dbID)
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
					fmt.Fprint(w, err.Error())
				} else {
					fmt.Fprint(w, result)
				}
			}
		} else if req.Method == "PUT" {
			body, err := ioutil.ReadAll(req.Body)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				fmt.Fprint(w, err.Error())
			} else {
				err := dbs[dbID].Set(string(body))
				if err != nil {
					w.WriteHeader(http.StatusBadRequest)
					fmt.Fprint(w, err.Error())
				} else {
					fmt.Fprintf(w, "OK")
				}
			}
		} else if req.Method == "DELETE" {
			body, err := ioutil.ReadAll(req.Body)

			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				fmt.Fprint(w, err.Error())
				return
			}

			err = dbs[dbID].Delete(string(body))
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				fmt.Fprint(w, err.Error())
			} else {
				fmt.Fprintf(w, "OK")
			}
		} else {
			w.WriteHeader(http.StatusMethodNotAllowed)
			fmt.Fprintf(w, "Invalid operation")
		}
	}
}
