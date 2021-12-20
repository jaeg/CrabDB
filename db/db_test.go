package db

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_New_DB(t *testing.T) {
	db := NewDB("1")
	assert.NotEqual(t, nil, db, "shouldn't be nil")
}

func Test_DB_Set(t *testing.T) {
	db := NewDB("1")
	db.NoJournal = true
	input := "{\"test\":0}"

	err := db.Set(input)

	assert.Equal(t, nil, err, "shouldn't error setting value")
}

func Test_DB_Get(t *testing.T) {
	db := NewDB("1")
	db.NoJournal = true
	input := "{\"test\":0}"

	err := db.Set(input)

	assert.Equal(t, nil, err, "shouldn't error setting value")

	value, err := db.Get("test")

	assert.Equal(t, nil, err, "shouldn't error getting value")

	assert.Equal(t, "0", value, "should equal 0")
}

func Test_DB_Delete(t *testing.T) {
	db := NewDB("1")
	db.NoJournal = true
	input := "{\"test\":0}"

	err := db.Set(input)

	assert.Equal(t, nil, err, "shouldn't error setting value")

	err = db.Delete("test")
	assert.Equal(t, nil, err, "shouldn't error deleting value")

	value, err := db.Get("test")

	assert.Equal(t, nil, err, "shouldn't error getting value")

	assert.NotEqual(t, "0", value, "value shouldn't be 0")
}
