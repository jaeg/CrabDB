package db

import (
	"testing"
)

func Test_New_DB(t *testing.T) {
	db := NewDB("1")
	if db == nil {
		t.Errorf("New DB returned nil")
	}
}

func Test_DB_Set(t *testing.T) {
	db := NewDB("1")
	db.NoJournal = true
	input := "{\"test\":0}"

	err := db.Set(input)

	if err != nil {
		t.Errorf("Error setting value in db %s", err.Error())
	}
}

func Test_DB_Get(t *testing.T) {
	db := NewDB("1")
	db.NoJournal = true
	input := "{\"test\":0}"

	err := db.Set(input)

	if err != nil {
		t.Errorf("Error setting value in db %s", err.Error())
	}

	value, err := db.Get("test")

	if err != nil {
		t.Errorf("Error getting value in db %s", err.Error())
	}

	if value != "0" {
		t.Errorf("Value in DB %s expect 0", value)

	}
}

func Test_DB_Delete(t *testing.T) {
	db := NewDB("1")
	db.NoJournal = true
	input := "{\"test\":0}"

	err := db.Set(input)

	if err != nil {
		t.Errorf("Error setting value in db %s", err.Error())
	}

	err = db.Delete("test")

	if err != nil {
		t.Errorf("Error deleting value in db %s", err.Error())
	}

	value, err := db.Get("test")

	if err != nil {
		t.Errorf("Error getting value in db %s", err.Error())
	}

	if value == "0" {
		t.Errorf("Value in DB %s expect it to not exist", value)

	}
}
