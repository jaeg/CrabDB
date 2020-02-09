package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/ioutil"
	"strings"

	"github.com/google/logger"
)

type DB struct {
	Raw string
}

func NewDB() *DB {
	db := &DB{}
	db.Raw = "{}"
	return db
}

func LoadDB(path string, encryptionKey string) *DB {
	db := &DB{}
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

func (this *DB) Set(input string) error {
	result, err := applyJSON(this.Raw, input)
	if err != nil {
		return err
	}
	this.Raw = result
	return nil
}

func (this *DB) Get(query string) (string, error) {
	var result map[string]interface{}
	err := json.Unmarshal([]byte(this.Raw), &result)
	if err != nil {
		return "", err
	}

	entries := strings.Split(query, ".")

	entry, err := getEntry(result, entries)
	if err != nil {
		return "", err
	} else {
		outputBytes, err := json.Marshal(entry)
		if err != nil {
			return "", err
		} else {
			return string(outputBytes), nil
		}
	}
}

func (this *DB) Delete(key string) error {
	var result map[string]interface{}
	err := json.Unmarshal([]byte(this.Raw), &result)
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

	this.Raw = string(outputBytes)
	return nil
}

func (this *DB) Save(path string, encryptionKey string) {
	outputBytes := []byte(this.Raw)
	if encryptionKey != "" {
		outputBytes = encrypt(outputBytes, encryptionKey)
	}
	err := ioutil.WriteFile(path, outputBytes, 0644)
	if err != nil {
		logger.Error(err)
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
