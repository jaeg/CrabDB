package token

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

const jwtKey = "12345678910111213141516171819202122232425262728293032"

func Test_Creating_A_JWT_Factory(t *testing.T) {
	factory, err := NewJWTTokenFactory(jwtKey)
	assert.Equal(t, nil, err, "shouldn't error creating factory")
	assert.NotEqual(t, nil, factory, "shouldn't return nil factory")
}

func Test_Creating_A_JWT_Factory_With_Too_Short_of_Key_Fails(t *testing.T) {
	_, err := NewJWTTokenFactory("short")
	assert.NotEqual(t, nil, err, "should error creating factory")

}

func Test_Creating_A_JWT_Token(t *testing.T) {
	factory, err := NewJWTTokenFactory(jwtKey)

	assert.Equal(t, nil, err, "shouldn't error creating factory")

	token, err := factory.CreateToken("test", time.Hour)
	assert.Equal(t, nil, err, "shouldn't error creating token")

	assert.NotEqual(t, 0, len(token), "should get a token back")
}

func Test_Verifying_JWT_Token_Fails(t *testing.T) {
	factory, err := NewJWTTokenFactory(jwtKey)

	assert.Equal(t, nil, err, "shouldn't error creating factory")

	token, err := factory.CreateToken("test", time.Hour)
	assert.Equal(t, nil, err, "shouldn't error creating token")

	_, err = factory.VerifyToken(token + "invalid junk")

	assert.NotEqual(t, nil, err, "shouldn error verifying token")
}

func Test_Verifying_JWT_Token(t *testing.T) {
	factory, err := NewJWTTokenFactory(jwtKey)

	assert.Equal(t, nil, err, "shouldn't error creating factory")

	token, err := factory.CreateToken("test", time.Hour)
	assert.Equal(t, nil, err, "shouldn't error creating token")

	payload, err := factory.VerifyToken(token)

	assert.Equal(t, nil, err, "shouldn't error verifying token")
	assert.NotEqual(t, nil, payload, "payload shouldn't be nil")
	assert.Equal(t, "test", payload.Username, "username should match")
}
