package auth

import "net/http"

type AuthMiddlewareInterface interface {
	Auth(next http.HandlerFunc) http.HandlerFunc
	HandleAuth(w http.ResponseWriter, r *http.Request)
}
