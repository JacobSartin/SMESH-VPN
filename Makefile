.PHONY: all client server

all: clean client server

client:
	env GOOS=linux GOARCH=amd64 go build -o bin/smesh-client_linux_amd64.exe ./cmd/client
	env GOOS=windows GOARCH=amd64 go build -o bin/smesh-client_windows_amd64.exe ./cmd/client

server:
	env GOOS=linux GOARCH=amd64 go build -o bin/smesh-server_linux_amd64.exe ./cmd/server
	env GOOS=windows GOARCH=amd64 go build -o bin/smesh-server_windows_amd64.exe ./cmd/server

clean:
	rm -rf bin/