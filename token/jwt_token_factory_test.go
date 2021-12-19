package token

import (
	"testing"
	"time"
)

const jwtKey = "12345678910111213141516171819202122232425262728293032"

func Test_Creating_A_JWT_Factory(t *testing.T) {
	factory, err := NewJWTTokenFactory(jwtKey)

	if err != nil {
		t.Errorf("Error on factory creation %s", err.Error())
	}

	if factory == nil {
		t.Errorf("No jwt factory returned")
	}
}

func Test_Creating_A_JWT_Factory_With_Too_Short_of_Key_Fails(t *testing.T) {
	factory, err := NewJWTTokenFactory("short")

	if err != nil {
		t.Errorf("Error on factory creation %s", err.Error())
	}

	if factory == nil {
		t.Errorf("No jwt factory returned")
	}
}

func Test_Creating_A_JWT_Token(t *testing.T) {
	factory, err := NewJWTTokenFactory(jwtKey)

	if err != nil {
		t.Errorf("Error on factory creation %s", err.Error())
	}

	token, err := factory.CreateToken("test", time.Hour)
	if err != nil {
		t.Errorf("Error on jwt token creation %s", err.Error())
	}

	if len(token) == 0 {
		t.Errorf("Invalid token")
	}
}

func Test_Verifying_JWT_Token_Fails(t *testing.T) {
	factory, err := NewJWTTokenFactory(jwtKey)

	if err != nil {
		t.Errorf("Error on factory creation %s", err.Error())
	}

	token, err := factory.CreateToken("test", time.Hour)
	if err != nil {
		t.Errorf("Error on jwt token creation %s", err.Error())
	}

	payload, err := factory.VerifyToken(token + "invalid junk")

	if err != nil {
		t.Errorf("Error on jwt token creation %s", err.Error())
	}
	if payload != nil {
		if payload.Username != "test" {
			t.Errorf("Token decryption failed expect %s, got %s", "test", payload.Username)
		}
	}
}

func Test_Verifying_JWT_Token(t *testing.T) {
	factory, err := NewJWTTokenFactory(jwtKey)

	if err != nil {
		t.Errorf("Error on factory creation %s", err.Error())
	}

	token, err := factory.CreateToken("test", time.Hour)
	if err != nil {
		t.Errorf("Error on jwt token creation %s", err.Error())
	}

	payload, err := factory.VerifyToken(token)

	if err != nil {
		t.Errorf("Error on jwt token creation %s", err.Error())
	}
	if payload != nil {
		if payload.Username != "test" {
			t.Errorf("Token decryption failed expect %s, got %s", "test", payload.Username)
		}
	}
}
