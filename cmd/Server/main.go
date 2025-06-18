package main

import (
	"fmt"
	"log"
	"net"
	"time"

	session "github.com/JacobSartin/SMESH-VPN/pkg/Session"
)

func main() {
	fmt.Println("SMESH-VPN discovery server starting...")

	// Create a client identity (in a real app, you'd load this from config/certs)
	identity := session.NewClientIdentity()

	// Create a session manager
	cleanupInterval := 5 * time.Minute
	maxIdleTime := 30 * time.Minute
	maxKeyAge := 24 * time.Hour
	sessionManager := session.NewSessionManager(cleanupInterval, maxIdleTime, maxKeyAge, identity)

	// Set up event handling - Option 1: Using a channel
	eventChannel := make(chan session.SessionEvent, 10)
	sessionManager.SetEventChannel(eventChannel)

	// Start a goroutine to handle events from the channel
	go func() {
		for event := range eventChannel {
			switch event.Type {
			case session.SessionEventConnected:
				fmt.Printf("New connection established! Session ID: %s\n", event.SessionID.String())
				if event.Session != nil {
					peerInfo := event.Session.PeerInfo()
					fmt.Printf("Peer address: %s\n", peerInfo.Address)
				}
			case session.SessionEventDisconnected:
				fmt.Printf("Session disconnected: %s\n", event.SessionID.String())
			case session.SessionEventError:
				fmt.Printf("Session error: %v\n", event.Error)
			}
		}
	}()

	// Set up event handling - Option 2: Using a callback function
	sessionManager.AddEventHandler(func(event session.SessionEvent) {
		switch event.Type {
		case session.SessionEventConnected:
			log.Printf("Event handler: New session %s connected", event.SessionID.String())
		case session.SessionEventDisconnected:
			log.Printf("Event handler: Session %s disconnected", event.SessionID.String())
		case session.SessionEventError:
			log.Printf("Event handler: Session error: %v", event.Error)
		}
	})

	// Start listening for connections
	listener, err := net.Listen("tcp", ":8080")
	if err != nil {
		log.Fatalf("Failed to start listener: %v", err)
	}
	defer listener.Close()

	fmt.Println("Server listening on :8080")

	// This will block and handle incoming connections
	// Each new connection will trigger the event handlers above
	if err := sessionManager.ListenForNewConnections(listener); err != nil {
		log.Fatalf("Failed to listen for connections: %v", err)
	}
}
