package db

import (
	"testing"
)

func Test_Apply_JSON_Valid_Input_And_Original(t *testing.T) {
	input := "{\"test\":0}"
	original := "{\"test\":1}"
	expected := "{\"test\":0}"

	output, err := applyJSON(original, input)

	if err == nil {
		if expected != output {
			t.Errorf("Expected %s got %s", expected, output)
		}
	} else {
		t.Errorf("Failed to apply json %s", err)
	}

}

func Test_Apply_JSON_Valid_Input_And_Invalid_Original(t *testing.T) {
	input := "{\"test\":0}"
	original := "{\"test:1}"

	_, err := applyJSON(original, input)
	if err == nil {
		t.Errorf("Expected error and didn't get one")
	} else {
		if err.Error() != "invalid original json" {
			t.Errorf("Failed to throw correct error")
		}
	}

}

func Test_Apply_JSON_Invalid_Input_And_Valid_Original(t *testing.T) {
	input := "{\"test:0}"
	original := "{\"test\":1}"

	_, err := applyJSON(original, input)
	if err == nil {
		t.Errorf("Expected error and didn't get one")
	} else {
		if err.Error() != "invalid input json" {
			t.Errorf("Failed to throw correct error")
		}
	}

}
