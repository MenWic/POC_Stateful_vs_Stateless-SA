package main

import (
	"log"

	"session-vs-jwt-poc/internal/application"
)

func main() {
	if err := application.Run(application.Options{
		Method:            "JWT stateless",
		DefaultPort:       "8082",
		DefaultInstanceID: "jwt-1",
		JWTEnabled:        true,
	}); err != nil {
		log.Fatal(err)
	}
}
