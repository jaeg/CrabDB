package journal

import (
	"encoding/json"
	"os"

	"github.com/google/logger"
)

var LogLocation string

//LogMessage represents a database operation.
type LogMessage struct {
	Operation string
	Input     string
	DBID      string
}

func Log(operation string, input string, dbId string) error {
	logFile, err := os.OpenFile(LogLocation+"/logfile.txt", os.O_RDWR|os.O_APPEND|os.O_CREATE, 0755)
	if err != nil {
		logger.Errorf("Error logging %s", err.Error())
		return err
	}

	newLog := LogMessage{Operation: operation, Input: input, DBID: dbId}

	outputBytes, err := json.Marshal(newLog)
	if err != nil {
		logger.Error(err)
		return err
	}

	/*
		if EncryptionKey != "" {
			outputBytes = crypt.Encrypt(outputBytes, EncryptionKey)
		}*/

	_, err = logFile.WriteString(string(outputBytes) + "\n")
	if err != nil {
		logger.Error(err)
	}

	defer logFile.Close()

	return nil
}
