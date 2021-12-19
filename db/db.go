package db

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"os"
	"strings"

	"github.com/google/logger"
	"github.com/jaeg/CrabDB/crypt"
	"github.com/jaeg/CrabDB/journal"
)

var EncryptionKey string

//DB represents the database
type DB struct {
	ID             string
	Raw            string
	Logs           []journal.LogMessage
	CurrentLogFile *os.File
	LogPlayback    bool
}

//NewDB creates a new instance of the database
func NewDB(dbID string) *DB {
	db := &DB{}
	db.Raw = "{}"
	db.ID = dbID
	return db
}

//LoadDB Loads a database from a file using an encryptionKey
func LoadDB(path string, encryptionKey string, id string) *DB {
	db := &DB{ID: id}
	dat, err := ioutil.ReadFile(path)
	if err != nil {
		logger.Errorf("Failed loading file: %s", err)
	} else {
		if encryptionKey != "" {
			dat, err = crypt.Decrypt([]byte(dat), encryptionKey)
			if err != nil {
				logger.Error("Error decrypting database")
				panic(err)
			}
		}
		db.Raw = string(dat)
	}
	return db
}

//Set sets the input in the database
func (c *DB) Set(input string) error {
	//Don't log to the journal if you are a playback.
	if !c.LogPlayback {
		journal.Log("set", input, c.ID)
	}

	result, err := applyJSON(c.Raw, input)
	if err != nil {
		return err
	}
	c.Raw = result
	return nil
}

//Get Gets the query's value from the database
func (c *DB) Get(query string) (string, error) {
	var result map[string]interface{}
	err := json.Unmarshal([]byte(c.Raw), &result)
	if err != nil {
		return "", err
	}

	entries := strings.Split(query, ".")

	entry, err := getEntry(result, entries)
	if err != nil {
		return "", err
	}
	outputBytes, err := json.Marshal(entry)
	if err != nil {
		return "", err
	}
	return string(outputBytes), nil

}

//Delete deletes the entry in the database
func (c *DB) Delete(key string) error {
	//Don't log to the journal if you are a playback.
	if !c.LogPlayback {
		journal.Log("delete", key, c.ID)
	}
	var result map[string]interface{}
	err := json.Unmarshal([]byte(c.Raw), &result)
	if err != nil {
		return err
	}
	entries := strings.Split(key, ".")

	result, err = deleteEntry(result, entries)

	if err != nil {
		return err
	}

	outputBytes, err := json.Marshal(result)
	if err != nil {
		return err
	}

	c.Raw = string(outputBytes)
	return nil
}

//Save saves the database with the given encryption key
func (c *DB) Save(path string, encryptionKey string) {
	outputBytes := []byte(c.Raw)
	var err error
	if encryptionKey != "" {
		outputBytes, err = crypt.Encrypt(outputBytes, encryptionKey)
		if err != nil {
			logger.Error("Error encrypting database")
			panic(err)
		}
	}
	err = ioutil.WriteFile(path, outputBytes, 0644)
	if err != nil {
		logger.Error(err)
	}
}

func applyJSON(o string, i string) (output string, outErr error) {
	var result map[string]interface{}
	err := json.Unmarshal([]byte(o), &result)
	if err != nil {
		outErr = errors.New("invalid original json")
		return
	}

	var input map[string]interface{}
	err = json.Unmarshal([]byte(i), &input)
	if err != nil {
		outErr = errors.New("invalid input json")
		return
	}

	for k, v := range input {
		result[k] = v
	}

	outputBytes, err := json.Marshal(result)
	if err != nil {
		outErr = errors.New("resulting JSON failed to marshal")
		return
	}

	output = string(outputBytes)

	return
}

func deleteEntry(m map[string]interface{}, entries []string) (map[string]interface{}, error) {
	if len(entries) == 0 || entries[0] == "" {
		return nil, errors.New("no entries to process")
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
		return nil, errors.New("no entries to process")
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
