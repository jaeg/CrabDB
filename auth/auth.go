package auth

import (
	"net/http"

	"github.com/google/logger"
)

var currentMiddleware AuthMiddlewareInterface

func UseMiddleware(middleware AuthMiddlewareInterface) {
	currentMiddleware = middleware
}

func Auth(next http.HandlerFunc) http.HandlerFunc {
	if currentMiddleware == nil {
		logger.Error("No middleware set")

		return http.NotFoundHandler().ServeHTTP
	}

	return currentMiddleware.Auth(next)
}

func HandleAuth(w http.ResponseWriter, r *http.Request) {
	if currentMiddleware == nil {
		logger.Error("No middleware set")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	currentMiddleware.HandleAuth(w, r)
}
