package util

import (
	"encoding/json"
	"hybrid/errorcode"

	couchdb "github.com/leesper/couchdb-golang"
)

// OffchainData struct
type OffchainData struct {
	FromMSP    string `json:"fromMSP"`
	ToMSP      string `json:"toMSP"`
	Data       string `json:"data"`
	DataHash   string `json:"dataHash"`
	TimeStamp  string `json:"timeStamp"`
	DocumentID string `json:"id"`
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
	x.DocumentID = x.ID
	// filter out unwanted fields
	x.ID = ""
	x.Rev = ""
	// do the marshalling
	return json.Marshal(x)
}

type Signature struct {
	Signature   string `json:"signature"`
	Algorithm   string `json:"algorithm"`
	Certificate string `json:"certificate"`
	Timestamp   string `json:"timestamp"`
}

// extract a single field from input json
func ExtractFieldFromJSON(jsonInput string, field string) (string, error) {
	var input map[string]interface{}
	err := json.Unmarshal([]byte(jsonInput), &input)
	if err != nil {
		return "", errorcode.Internal.WithMessage("failed to parse signature json, %v", err).LogReturn()
	}

	// try to extract the value
	value, exists := input[field].(string)
	if !exists {
		return "", errorcode.Internal.WithMessage("failed to parse signature json, missing field %s", field).LogReturn()
	}

	return value, nil
}
