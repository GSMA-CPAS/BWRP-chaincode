// Copyright the BWRP-chaincode contributors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
package data

import (
	"encoding/base64"
	"hybrid/util"
)

// Document structure
type Document struct {
	Payload     string
	PayloadHash string
}

var data = "data1234"
var payload = base64.StdEncoding.EncodeToString([]byte(data))
var payloadHash = util.CalculateHash(payload)

// ExampleDocument : a test document:
var ExampleDocument = Document{
	Payload:     payload,
	PayloadHash: payloadHash,
}
