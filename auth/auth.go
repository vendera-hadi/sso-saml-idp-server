package auth

// Mock user database
var users = map[string]string{
	"user1": "password1",
	"user2": "password2",
}

func ValidateCredential(username, password string) bool {
	// YOU CAN CHANGE IT TO USE ANOTHER DATABASE ...
	if pass, ok := users[username]; ok && pass == password {
		return true
	}
	return false
}
