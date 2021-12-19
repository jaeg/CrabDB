package crypt

import (
	"testing"
)

const inputConstant = "I'mSomeGoodInput"
const passphrase = "I'mASecurePassphrase"

func TestValuesEncryptedAreDecryptable(t *testing.T) {
	encrypted, err := Encrypt([]byte(inputConstant), passphrase)

	if err != nil {
		t.Errorf("Error on the encrypt %s", err.Error())
	}

	decrypted, err := Decrypt(encrypted, passphrase)
	if err != nil {
		t.Errorf("Error on the decrypt %s", err.Error())
	}

	if string(decrypted) != inputConstant {
		t.Errorf("Expected %s got %s", inputConstant, string(decrypted))
	}
}
