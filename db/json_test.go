package db

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_Apply_JSON_Valid_Input_And_Original(t *testing.T) {
	input := "{\"test\":0}"
	original := "{\"test\":1}"
	expected := "{\"test\":0}"

	output, err := applyJSON(original, input)

	assert.Equal(t, nil, err, "shouldn't error applying json")

	if err == nil {
		assert.Equal(t, expected, output, "value should match")
	}

}

func Test_Apply_JSON_Valid_Input_And_Invalid_Original(t *testing.T) {
	input := "{\"test\":0}"
	original := "{\"test:1}"

	_, err := applyJSON(original, input)

	assert.NotEqual(t, nil, err, "should error applying json")

	assert.Equal(t, err.Error(), "invalid original json", "wrong error returned")

}

func Test_Apply_JSON_Invalid_Input_And_Valid_Original(t *testing.T) {
	input := "{\"test:0}"
	original := "{\"test\":1}"

	_, err := applyJSON(original, input)

	assert.NotEqual(t, nil, err, "should error applying json")

	assert.Equal(t, err.Error(), "invalid input json", "wrong error returned")
}
