package manager

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

const testUserName = "testUser"
const deleteMeUsername = "deleteMe"

func Test_Get_User_That_Does_Not_Exist_Fails(t *testing.T) {
	user, err := GetUser(testUserName)

	assert.NotEqual(t, nil, err, "should have error")
	assert.Equal(t, "no user", err.Error(), "should error with no user")
	assert.Nil(t, user, "user shouldn't exist")
}

func Test_Get_User_With_No_Username_Errors(t *testing.T) {
	user, err := GetUser("")

	assert.NotEqual(t, nil, err, "should error getting user after delete")
	assert.Equal(t, "no username provided", err.Error(), "should error with no user")
	assert.Nil(t, user, "should of deleted the user")
}

func Test_Create_User(t *testing.T) {
	user := User{Username: testUserName}
	CreateUser(user)

	user2, err := GetUser(testUserName)

	assert.Equal(t, nil, err, "shouldn't error creating user")
	assert.NotEqual(t, nil, user2, "should of created a user")
	assert.Equal(t, user2.Username, testUserName, "should of created a user")

	DeleteUser(testUserName)
}

func Test_Update_User(t *testing.T) {
	user := User{Username: testUserName}
	CreateUser(user)

	user2, err := GetUser(testUserName)

	assert.Equal(t, nil, err, "shouldn't error getting user before")
	assert.NotEqual(t, nil, user2, "should of created a user")
	assert.Equal(t, user2.Username, testUserName, "should of created a user")

	user.Access = "1,2,3"
	UpdateUser(user)

	user2, err = GetUser(testUserName)

	assert.Equal(t, nil, err, "shouldn't error getting user after update")
	assert.Equal(t, "1,2,3", user2.Access, "should of updated the user")

	DeleteUser(testUserName)
}

func Test_Delete_User(t *testing.T) {
	user := User{Username: deleteMeUsername}
	CreateUser(user)

	user2, err := GetUser(deleteMeUsername)

	assert.Equal(t, nil, err, "shouldn't error getting user before delete")
	assert.NotNil(t, user2, "should of created a user")

	err = DeleteUser(deleteMeUsername)
	assert.Equal(t, nil, err, "shouldn't error deleting user")

	user2, err = GetUser(deleteMeUsername)

	assert.NotEqual(t, nil, err, "should error getting user after delete")
	assert.Equal(t, "no user", err.Error(), "should error with no user")
	assert.Nil(t, user2, "should of deleted the user")
}

func Test_Delete_User_With_No_Username_Errors(t *testing.T) {
	err := DeleteUser("")

	assert.NotEqual(t, nil, err, "should error getting user after delete")
	assert.Equal(t, "no username provided", err.Error(), "should error with no user")
}

func Test_Delete_User_That_Does_Not_Exist_Errors(t *testing.T) {
	err := DeleteUser("asakdlfasdf")

	assert.NotEqual(t, nil, err, "should error getting user after delete")
	assert.Equal(t, "no user", err.Error(), "should error with no user")
}
