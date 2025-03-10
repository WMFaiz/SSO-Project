package Structs

import "sync"

type User struct {
	ID       string
	Email    string
	JwtToken string
	Status   string
}

var UsersStore = struct {
	sync.RWMutex
	Users map[string]User
}{Users: make(map[string]User)}

func GetUser(email string, status string) *User {
	UsersStore.Lock()
	defer UsersStore.Unlock()
	for _, user := range UsersStore.Users {
		if user.Email == email {
			if user.Status == status {
				return &user
			}
		}
	}
	return nil
}

func DeleteUser(userId string) bool {
	UsersStore.Lock()
	defer UsersStore.Unlock()
	if _, exists := UsersStore.Users[userId]; exists {
		delete(UsersStore.Users, userId)
		return true
	}
	return false
}
