package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
)

var db = "{}"

func main() {
	fmt.Println("CrabDB Started")

	http.HandleFunc("/db", handleDB)

	http.ListenAndServe(":8090", nil)
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
	if req.Method == "GET" {
		fmt.Fprintf(w, db)
	} else if req.Method == "PUT" {
		body, err := ioutil.ReadAll(req.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, err.Error())
		} else {
			result, err := applyJSON(db, string(body))
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				fmt.Fprintf(w, err.Error())
			} else {
				db = result
				fmt.Fprintf(w, "OK")
			}
		}

	} else if req.Method == "DELETE" {
		var result map[string]interface{}
		err := json.Unmarshal([]byte(db), &result)
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
			return
		}

		outputBytes, err := json.Marshal(result)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, err.Error())
			return
		}

		db = string(outputBytes)
		fmt.Fprintf(w, "OK")
	} else {
		w.WriteHeader(http.StatusMethodNotAllowed)
		fmt.Fprintf(w, "Invalid operation")
	}
}
