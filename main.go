package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"sync"

	"github.com/gorilla/mux"
)

var dbs map[string]string
var locks map[string]*sync.Mutex

func main() {
	fmt.Println("CrabDB Started")

	dbs = make(map[string]string)
	locks = make(map[string]*sync.Mutex)

	r := mux.NewRouter()
	r.HandleFunc("/db/{id}", handleDB)

	http.ListenAndServe(":8090", r)
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
