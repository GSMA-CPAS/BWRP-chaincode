package util

import (
	"encoding/json"
	"hybrid/errorcode"
	"unicode"

	jsoniter "github.com/json-iterator/go"
	"github.com/json-iterator/go/extra"

	couchdb "github.com/leesper/couchdb-golang"
)

// BlockchainRef struct
type BlockchainRef struct {
	Type      string
	TxID      string
	Timestamp string
}

// OffchainData struct
type OffchainData struct {
	FromMSP       string
	ToMSP         string
	Payload       string
	PayloadHash   string
	BlockchainRef BlockchainRef
	ReferenceID   string
	couchdb.Document
}

// marshal all json to use lowercase camelcase keys
// a in the same way as expected in nodejs
func MarshalLowerCamelcaseJSON(v interface{}) ([]byte, error) {
	var json = jsoniter.ConfigCompatibleWithStandardLibrary
	extra.SetNamingStrategy(LowercaseStartingCamelcase)
	return json.Marshal(v)
}

// marshal all json to use lowercase camelcase keys
// a in the same way as expected in nodejs
func UnmarshalLowerCamelcaseJSON(data []byte, v interface{}) error {
	var json = jsoniter.ConfigCompatibleWithStandardLibrary
	return json.Unmarshal(data, v)
}

func LowercaseStartingCamelcase(name string) string {
	newName := []rune{}
	for i, c := range name {
		if i == 0 {
			newName = append(newName, unicode.ToLower(c))
		} else {
			newName = append(newName, c)
		}
	}
	return string(newName)
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

	// cleanup
	x.ID = ""
	x.Rev = ""

	// do the marshalling
	return MarshalLowerCamelcaseJSON(x)
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
