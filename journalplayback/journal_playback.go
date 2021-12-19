package journalplayback

import (
	"bufio"
	"encoding/json"
	"os"

	"github.com/google/logger"
	"github.com/jaeg/CrabDB/db"
	"github.com/jaeg/CrabDB/journal"
)

//PlayLogs plays back a log file and returns the resulting db
func PlayLogs(path string) map[string]*db.DB {
	logger.Info("Playing logs ", path)
	logsFile, err := os.Open(path)
	if err != nil {
		logger.Errorf("Failed loading file: %s", err)
		return nil
	}
	defer logsFile.Close()

	ldbs := make(map[string]*db.DB)

	scanner := bufio.NewScanner(logsFile)
	scanner.Split(bufio.ScanLines)

	for scanner.Scan() {
		logRaw := scanner.Text()
		/*
			if EncryptionKey != "" {
				dat := decrypt([]byte(logRaw), EncryptionKey)
				logRaw = string(dat)
			}*/
		var logM journal.LogMessage
		err := json.Unmarshal([]byte(logRaw), &logM)
		if err != nil {
			logger.Error(err)
			return nil
		}

		if ldbs[logM.DBID] == nil {
			ldbs[logM.DBID] = db.NewDB(logM.DBID)
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
