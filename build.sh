#!/bin/sh
export GOPATH=$(pwd)/requirements
export GOBIN=$(pwd)/bin 
mkdir -p ${GOPATH}
go get github.com/miekg/dns
go install src/server.go
