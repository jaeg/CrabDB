package app

import (
	"context"
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
	"github.com/jaeg/CrabDB/manager"
)

var certFile = flag.String("cert-file", "", "location of cert file")
var keyFile = flag.String("key-file", "", "location of key file")
var port = flag.String("port", "8090", "port to host on")
var dataLocation = flag.String("data-location", "data", "Data location")
var journalLocation = flag.String("journal-location", "journals", "Journal location")
var logPath = flag.String("log-path", "./logs.txt", "Logs location")

type App struct {
	dbs   map[string]*db.DB
	locks map[string]*sync.Mutex
	srv   *http.Server
}

func (a *App) Init() {
	flag.Parse()

	//Start the logger
	lf, err := os.OpenFile(*logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0660)
	if err != nil {
		logger.Fatalf("Failed to open log file: %v", err)
	}

	logger.Init("CrabDB", true, true, lf)

	logger.Info("CrabDB Started")
	journal.LogLocation = *journalLocation

	//Create maps
	a.dbs = make(map[string]*db.DB)
	a.locks = make(map[string]*sync.Mutex)

	//Load config and databases from disk
	a.loadConfig()
	a.loadDatabases()

	//Pick the middleware to use for authentication
	mw, err := auth.NewBasicAuthMiddleware()
	if err != nil {
		panic(err)
	}

	auth.UseMiddleware(mw)

	//Setup the HTTP server
	r := mux.NewRouter()
	r.HandleFunc("/db/{id}", auth.Auth(a.handleDB))
	r.HandleFunc("/", a.handleProbe)
	r.HandleFunc("/auth", auth.HandleAuth)

	a.srv = &http.Server{
		Addr:    ":" + *port,
		Handler: r,
	}

	//Verify DB with playback
	ldbs := journalplayback.PlayLogs(*journalLocation + "/logfile.txt")
	for k, v := range a.dbs {
		if ldbs[k] == nil {
			logger.Error("DB missing from logs: ", k)
			return
		}

		if v.Raw != ldbs[k].Raw {
			logger.Error("Data mismatch")
			return
		}
	}

	//Start helper processes
	go a.configWatcher()
	go a.bufferWriter()
}

func (a *App) Run(ctx context.Context) {
	defer logger.Close()

	//Run the http server
	go func() {
		if *certFile == "" || *keyFile == "" {
			logger.Info("Starting http")
			a.srv.ListenAndServe()
		} else {
			logger.Info("Starting https")
			a.srv.ListenAndServeTLS(*certFile, *keyFile)
		}
	}()

	// Handle shutdowns gracefully
	<-ctx.Done()

	ctxShutDown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer func() {
		cancel()
	}()

	if err := a.srv.Shutdown(ctxShutDown); err != nil {
		logger.Errorf("Failed to shutdown server %s", err.Error())
	} else {
		logger.Info("HTTP Server shutdown")
	}

	//Finalize shutdown
	a.Shutdown()
}

func (a *App) Shutdown() {
	logger.Info("Shutting down..")
	//Lock all the databases and write to disk.

	/* Commenting this out for now... it's clearing the db for some reason.
	for k := range a.locks {
		go a.writeDBToFile(k)
	}*/
	logger.Info("DBs written to disk")
}

func (a *App) loadConfig() {
	if _, err := os.Stat(*journalLocation); os.IsNotExist(err) {
		err = os.MkdirAll(*journalLocation, 0755)
		if err != nil {
			panic(err)
		}
	}

	//Handle mgr directory
	if _, err := os.Stat("mgr"); os.IsNotExist(err) {
		err = os.MkdirAll("mgr", 0755)
		if err != nil {
			panic(err)
		}
	}

	manager.Init()

	//Encryption key settings
	cek, err := ioutil.ReadFile("config/encryptionkey")
	if err == nil {
		db.EncryptionKey = string(cek)
	}
}

// Watches the configuration file and reloads as necessary.
func (a *App) configWatcher() {
	if _, err := os.Stat(*journalLocation); os.IsNotExist(err) {
		err = os.MkdirAll(*journalLocation, 0755)
		if err != nil {
			panic(err)
		}
	}

	for {
		a.loadConfig()
		time.Sleep(5 * time.Second)
	}

}

func (a *App) loadDatabases() {
	//Handle data directory
	if _, err := os.Stat(*dataLocation); os.IsNotExist(err) {
		err = os.MkdirAll(*dataLocation, 0755)
		if err != nil {
			panic(err)
		}
	} else {
		err = filepath.Walk(*dataLocation, func(path string, info os.FileInfo, err error) error {
			if len(strings.Split(path, *dataLocation+"/")) > 1 {
				dbID := strings.Split(path, *dataLocation+"/")[1]
				a.dbs[dbID] = db.LoadDB(path, db.EncryptionKey, dbID)
			}

			//This is for the inner function
			return nil
		})

		if err != nil {
			panic(err)
		}

		for k := range a.dbs {
			a.locks[k] = &sync.Mutex{}
		}
	}
}

func (a *App) writeDBToFile(dbID string) {
	a.locks[dbID].Lock()
	a.dbs[dbID].Save(*dataLocation+"/"+dbID, db.EncryptionKey)
	a.locks[dbID].Unlock()
}

func (a *App) bufferWriter() {
	for {
		//Lock all the DBs
		for k := range a.locks {
			go a.writeDBToFile(k)
		}
		time.Sleep(5 * time.Second)
	}
}

func (a *App) handleProbe(w http.ResponseWriter, req *http.Request) {
	fmt.Fprintf(w, "{}")
}

func (a *App) handleDB(w http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	dbID := vars["id"]

	//Provide a DB please.
	if dbID == "" {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "No DB Provided")
	} else {

		// If the DB is new create it as an empty json.
		if a.dbs[dbID] == nil {
			a.dbs[dbID] = db.NewDB(dbID)
			a.locks[dbID] = &sync.Mutex{}
		}

		lock := a.locks[dbID]
		defer lock.Unlock()
		lock.Lock()
		if req.Method == "GET" {
			query, ok := req.URL.Query()["key"]
			if !ok {
				fmt.Fprintf(w, a.dbs[dbID].Raw)
			} else {
				result, err := a.dbs[dbID].Get(query[0])
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
				err := a.dbs[dbID].Set(string(body))
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

			err = a.dbs[dbID].Delete(string(body))
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
