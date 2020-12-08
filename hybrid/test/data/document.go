package data

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
)

// Document structure
type Document struct {
	Data64 string
	Tmp    []byte
	Hash   string
}

var data = "data1234"
var data64 = base64.StdEncoding.EncodeToString([]byte(data))
var tmp = sha256.Sum256([]byte(data64))

// ExampleDocument : a test document:
var ExampleDocument = Document{
	Data64: data64,
	Tmp:    tmp[:],
	Hash:   hex.EncodeToString(tmp[:]),
}
