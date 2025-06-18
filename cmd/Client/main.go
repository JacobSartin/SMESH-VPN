package main

import (
	"fmt"
	"log"
	"time"

	session "github.com/JacobSartin/SMESH-VPN/pkg/Session"
	"github.com/google/uuid"
)

func main() {
	fmt.Println("SMESH-VPN client starting...")

	// Create a client identity
	identity := session.NewClientIdentity()

	// Create a session manager
	cleanupInterval := 5 * time.Minute
	maxIdleTime := 30 * time.Minute
	maxKeyAge := 24 * time.Hour
	sessionManager := session.NewSessionManager(cleanupInterval, maxIdleTime, maxKeyAge, identity)

	// Set up event handling
	eventChannel := make(chan session.SessionEvent, 10)
	sessionManager.SetEventChannel(eventChannel)

	// Start event handler
	go func() {
		for event := range eventChannel {
			switch event.Type {
			case session.SessionEventConnected:
				fmt.Printf("Connected to server! Session ID: %s\n", event.SessionID.String())
			case session.SessionEventDisconnected:
				fmt.Printf("Disconnected from server: %s\n", event.SessionID.String())
			case session.SessionEventError:
				fmt.Printf("Connection error: %v\n", event.Error)
			}
		}
	}()

	// Connect to server
	serverAddr := "localhost:8080"
	fmt.Printf("Connecting to server at %s...\n", serverAddr)

	// Create peer info for the server
	serverPeerInfo := session.PeerInfo{
		ID: uuid.NullUUID{
			UUID:  uuid.New(),
			Valid: true,
		},
		// Address will be set when we establish the connection
		LastSeen: time.Now(),
	}

	// Create a session (this will establish the connection)
	newSession, err := sessionManager.CreateSession(serverPeerInfo)
	if err != nil {
		log.Fatalf("Failed to create session: %v", err)
	}

	fmt.Printf("Session created with ID: %s\n", newSession.SessionID().String())

	// Keep the client running
	fmt.Println("Client running... Press Ctrl+C to exit")
	select {} // Block forever
}
