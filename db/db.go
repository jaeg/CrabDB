package db

import (
	"encoding/json"
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
	NoJournal      bool
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
	if !c.LogPlayback && !c.NoJournal {
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
	if !c.LogPlayback && !c.NoJournal {
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
