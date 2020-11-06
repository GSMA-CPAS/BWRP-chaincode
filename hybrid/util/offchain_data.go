package util

import (
	couchdb "github.com/leesper/couchdb-golang"
)

// OffchainData struct
type OffchainData struct {
	FromMSP   string `json:"fromMSP"`
	ToMSP     string `json:"toMSP"`
	Data      string `json:"data"`
	DataHash  string `json:"dataHash"`
	TimeStamp string `json:"timeStamp"`
	couchdb.Document
}
