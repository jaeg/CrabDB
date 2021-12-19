package auth

import (
	"net/http"
)

type UnauthedMiddleware struct {
}

func NewUnauthedMiddleware() *UnauthedMiddleware {
	b := &UnauthedMiddleware{}

	return b
}

func (b *UnauthedMiddleware) HandleAuth(w http.ResponseWriter, r *http.Request) {

}

func (b *UnauthedMiddleware) Auth(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r)
	})
}
