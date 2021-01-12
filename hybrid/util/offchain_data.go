package util

import (
	"encoding/json"

	couchdb "github.com/leesper/couchdb-golang"
)

// OffchainData struct
type OffchainData struct {
	FromMSP     string `json:"fromMSP"`
	ToMSP       string `json:"toMSP"`
	Data        string `json:"data"`
	DataHash    string `json:"dataHash"`
	TimeStamp   string `json:"timeStamp"`
	ReferenceID string `json:"id"`
	couchdb.Document
}

// MarshalToCleanJSON is a custom marshaller for the OffchainData struct
// this is necessary as we want to return a "clean" json
// withouth the couchdb Document inclusion
// luckily the json exported fields in the couchdb doc are set to omit empty
// thus cleaning the entries will filter them out
func (d OffchainData) MarshalToCleanJSON() ([]byte, error) {
	type data OffchainData
	x := data(d)
	// copy to "custom" id
	x.ReferenceID = x.ID
	// filter out unwanted fields
	x.ID = ""
	x.Rev = ""
	// do the marshalling
	return json.Marshal(x)
}
