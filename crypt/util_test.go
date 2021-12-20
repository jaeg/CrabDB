package crypt

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

const inputConstant = "I'mSomeGoodInput"
const passphrase = "I'mASecurePassphrase"

func TestValuesEncryptedAreDecryptable(t *testing.T) {
	encrypted, err := Encrypt([]byte(inputConstant), passphrase)
	assert.Equal(t, nil, err, "shouldn't error on encrypt")

	decrypted, err := Decrypt(encrypted, passphrase)
	assert.Equal(t, nil, err, "shouldn't error on decrypt")

	assert.Equal(t, string(decrypted), inputConstant, "should be equal")
}
