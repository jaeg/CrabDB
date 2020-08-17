package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"github.com/google/logger"
)

//DB represents the database
type DB struct {
	ID             string
	Raw            string
	Logs           []LogMessage
	CurrentLogFile *os.File
	LogPlayback    bool
}

//LogMessage represents a database operation.
type LogMessage struct {
	Operation string
	Input     string
	DBID      string
}

//NewDB creates a new instance of the database
func NewDB(dbID string) *DB {
	db := &DB{}
	db.Raw = "{}"
	db.ID = dbID
	log.Print(dbID)

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
			dat = decrypt([]byte(dat), encryptionKey)
		}
		db.Raw = string(dat)
	}
	return db
}

//PlayLogs plays back a log file and returns the resulting db
func PlayLogs(path string) map[string]*DB {
	logsFile, err := os.Open(path)
	if err != nil {
		logger.Errorf("Failed loading file: %s", err)
		return nil
	}
	defer logsFile.Close()

	ldbs := make(map[string]*DB)

	scanner := bufio.NewScanner(logsFile)
	scanner.Split(bufio.ScanLines)

	for scanner.Scan() {
		logRaw := scanner.Text()
		var logM LogMessage
		err := json.Unmarshal([]byte(logRaw), &logM)
		if err != nil {
			logger.Error(err)
			return nil
		}

		if ldbs[logM.DBID] == nil {
			ldbs[logM.DBID] = NewDB(logM.DBID)
			ldbs[logM.DBID].LogPlayback = true
		}

		switch logM.Operation {
		case "set":
			ldbs[logM.DBID].Set(logM.Input)
		case "delete":
			ldbs[logM.DBID].Delete(logM.Input)
		}

	}
	return ldbs
}

//Set sets the input in the database
func (c *DB) Set(input string) error {
	c.log("set", input)
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
	c.log("delete", key)
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
	if encryptionKey != "" {
		outputBytes = encrypt(outputBytes, encryptionKey)
	}
	err := ioutil.WriteFile(path, outputBytes, 0644)
	if err != nil {
		logger.Error(err)
	}
}

func (c *DB) log(operation string, input string) {
	if !c.LogPlayback {
		log.Print("Logging message")
		logFile, err := os.OpenFile(*logLocation+"/logfile.txt", os.O_RDWR|os.O_APPEND|os.O_CREATE, 0755)
		if err != nil {
			panic(err)
		}

		newLog := LogMessage{Operation: operation, Input: input, DBID: c.ID}
		c.Logs = append(c.Logs, newLog)
		outputBytes, err := json.Marshal(newLog)
		if err != nil {
			logger.Error(err)
			return
		}

		_, err = logFile.WriteString(string(outputBytes) + "\n")
		if err != nil {
			logger.Error(err)
		}

		defer logFile.Close()
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
