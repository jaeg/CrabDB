package db

import (
	"encoding/json"
	"errors"
)

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
