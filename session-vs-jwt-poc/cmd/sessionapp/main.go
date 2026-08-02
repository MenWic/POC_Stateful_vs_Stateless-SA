package main

import (
	"log"

	"session-vs-jwt-poc/internal/application"
)

func main() {
	if err := application.Run(application.Options{
		Method:            "Sesiones stateful",
		DefaultPort:       "8081",
		DefaultInstanceID: "session-1",
		SessionsEnabled:   true,
	}); err != nil {
		log.Fatal(err)
	}
}
