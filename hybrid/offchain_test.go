// Copyright the BWRP-chaincode contributors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
package main

//see https://github.com/hyperledger/fabric-samples/blob/master/asset-transfer-basic/chaincode-go/chaincode/smartcontract_test.go

import (
	"encoding/json"
	"hybrid/errorcode"
	"hybrid/test/chaincode"
	. "hybrid/test/data"
	"hybrid/test/endpoint"
	"hybrid/util"
	"os"
	"testing"

	log "github.com/sirupsen/logrus"

	"github.com/stretchr/testify/require"
)

func verifyData(t *testing.T, dataJSON string, document *Document) {
	var data util.OffchainData

	// try to parse the data
	err := json.Unmarshal([]byte(dataJSON), &data)
	require.NoError(t, err)

	// compare stored values
	require.EqualValues(t, data.Payload, document.Payload)
	require.EqualValues(t, data.PayloadHash, document.PayloadHash)
}

func setupTestCase(t *testing.T) (func(t *testing.T), endpoint.Endpoint, endpoint.Endpoint) {
	testName := util.FunctionName(2)
	log.Infof("################################################################################")
	log.Infof("running test " + testName)
	log.Infof("################################################################################")

	// set up proper endpoints
	ep1, ep2 := endpoint.CreateEndpoints(t)

	cleanupFunc := func(t *testing.T) {
		log.Infof("finishing test " + testName + ", cleaning up endpoints...")

		// shut down dummy db
		ep1.Close()
		ep2.Close()
	}

	return cleanupFunc, ep1, ep2
}

func TestPrivateDocumentAccess(t *testing.T) {
	// set up
	cleanupFunc, ep1, ep2 := setupTestCase(t)
	defer cleanupFunc(t)

	// read private documents on ORG1 with ORG1 tx context
	response, err := ep1.FetchPrivateDocumentReferenceIDs(ep1)
	require.NoError(t, err)
	log.Info(response)

	// read private documents on ORG1 with ORG2 tx context
	response, err = ep1.FetchPrivateDocumentReferenceIDs(ep2)
	require.Error(t, err)
	log.Info(response)
}

func TestOffchainDBConfig(t *testing.T) {
	// set up
	cleanupFunc, ep1, ep2 := setupTestCase(t)
	defer cleanupFunc(t)

	// read back for debugging
	// note that this is not allowed on chaincode calls
	// as getOffchainDBConfig is not exported
	os.Setenv("CORE_PEER_LOCALMSPID", ORG1.Name)
	uri, err := ep1.GetOffchainDBConfig(ep1)
	require.NoError(t, err)
	log.Infof("read back uri <%s>\n", uri)

	// read back with txcontext ORG2 -> this has to fail!
	_, err = ep1.GetOffchainDBConfig(ep2)
	require.Error(t, err)

	// check if verify works
	err = ep1.CheckOffchainDBConfig(ep1)
	require.NoError(t, err)

	// break config:
	url := "http://0.1.2.3/nodb"
	err = ep1.SetOffchainDBConfig(url)
	// setting this will fail (connection refused)
	require.Error(t, err)
	// as this is broken now, this should fail
	err = ep1.CheckOffchainDBConfig(ep1)
	require.Error(t, err)
}

func TestExchangeAndSigning(t *testing.T) {
	// set up
	cleanupFunc, ep1, ep2 := setupTestCase(t)
	defer cleanupFunc(t)

	// calc referenceID
	referenceID, err := ep1.CreateReferenceID(ep2)
	require.NoError(t, err)
	log.Infof("got referenceID <%s>\n", referenceID)

	// QUERY store document on ORG1 (local)
	hash, err := ep1.StorePrivateDocument(ep1, ORG2.Name, referenceID, ExampleDocument.Payload)
	require.NoError(t, err)
	require.EqualValues(t, hash, ExampleDocument.PayloadHash)

	// QUERY store document on ORG2 (remote)
	hash, err = ep2.StorePrivateDocument(ep1, ORG2.Name, referenceID, ExampleDocument.Payload)
	require.NoError(t, err)
	require.EqualValues(t, hash, ExampleDocument.PayloadHash)

	// PUBLISH reference payload link on the ledger
	referencePayloadLink, err := ep1.CreateReferencePayloadLink(ep1, referenceID, ExampleDocument.PayloadHash)
	require.NoError(t, err)
	referenceKey := referencePayloadLink[0]
	referenceValue := referencePayloadLink[1]
	err = ep1.InvokePublishReferencePayloadLink(ep1, referenceKey, referenceValue)
	require.NoError(t, err)

	// VERIFY that ORG1 stored the document
	dataJSON, err := ep1.FetchPrivateDocument(ep1, referenceID)
	require.NoError(t, err)

	// VERIFY that the data store matches the uploaded data
	verifyData(t, dataJSON, &ExampleDocument)

	// just for testing, check all stored doc ids:
	response, err := ep1.FetchPrivateDocumentReferenceIDs(ep1)
	require.NoError(t, err)
	log.Info(response)

	// VERIFY that ORG2 stored the document
	dataJSON, err = ep2.FetchPrivateDocument(ep2, referenceID)
	require.NoError(t, err)

	// VERIFY that the data store matches the uploaded data
	verifyData(t, dataJSON, &ExampleDocument)

	// ### org1 signs document:
	signaturePayload := chaincode.CreateSignaturePayload(ORG1.Name, referenceID, referenceValue)
	signature, err := chaincode.SignPayload(signaturePayload, ORG1.PrivateKey, ORG1.UserCertificate)
	require.NoError(t, err)
	signatureJSON, err := json.Marshal(signature)
	require.NoError(t, err)

	// QUERY create storage key
	storagekeyORG1, err := ep1.CreateStorageKey(ep1, ORG1.Name, referenceID)
	require.NoError(t, err)

	// INVOKE storeSignature (here only org1, can also be all endorsers)
	err = ep1.InvokeStoreSignature(ep1, storagekeyORG1, string(signatureJSON))
	require.NoError(t, err)

	// INVOKE storeSignature with same signatureJSON should fail
	err = ep1.InvokeStoreSignature(ep1, storagekeyORG1, string(signatureJSON))
	require.Error(t, err)

	// ### org2 signs document:
	// QUERY create storage key
	storagekeyORG2, err := ep2.CreateStorageKey(ep2, ORG2.Name, referenceID)
	require.NoError(t, err)
	signaturePayload = chaincode.CreateSignaturePayload(ORG2.Name, referenceID, referenceValue)
	signature, err = chaincode.SignPayload(signaturePayload, ORG2.PrivateKey, ORG2.UserCertificate)
	require.NoError(t, err)
	signatureJSON, err = json.Marshal(signature)
	require.NoError(t, err)

	// INVOKE storeSignature (here only org1, can also be all endorsers)
	err = ep1.InvokeStoreSignature(ep2, storagekeyORG2, string(signatureJSON))
	require.NoError(t, err)

	// ### (optional) org1 checks signatures of org2 on document:
	// QUERY create expected key
	storagekeypartnerORG2, err := ep1.CreateStorageKey(ep1, ORG2.Name, referenceID)
	require.Equal(t, storagekeyORG2, storagekeypartnerORG2)
	require.NoError(t, err)
	// QUERY GetSignatures
	signatures, err := ep1.GetSignatures(ep1, ORG2.Name, storagekeypartnerORG2)
	require.NoError(t, err)
	chaincode.PrintSignatureResponse(signatures)

	// ### (optional) org2 checks signatures of org1 on document:
	// QUERY create expected key
	storagekeypartnerORG1, err := ep2.CreateStorageKey(ep2, ORG1.Name, referenceID)
	require.NoError(t, err)
	// QUERY GetSignatures
	signatures, err = ep2.GetSignatures(ep2, ORG1.Name, storagekeypartnerORG1)
	require.NoError(t, err)
	chaincode.PrintSignatureResponse(signatures)
	// QUERY verify signatures of ORG1
	verification, err := ep2.VerifySignatures(ep2, referenceID, ORG1.Name, ORG1.Name)
	require.NoError(t, err)
	err = chaincode.CheckSignatureResponse(verification)
	require.NoError(t, err)

	// QUERY verify signatures of ORG2
	verification, err = ep2.VerifySignatures(ep2, referenceID, ORG1.Name, ORG2.Name)
	require.NoError(t, err)
	err = chaincode.CheckSignatureResponse(verification)
	require.NoError(t, err)
}

func TestStoreDocumentPayloadLink(t *testing.T) {
	// set up
	cleanupFunc, ep1, ep2 := setupTestCase(t)
	defer cleanupFunc(t)

	// calc referenceID
	referenceID, err := ep1.CreateReferenceID(ep2)
	require.NoError(t, err)
	log.Infof("got referenceID <%s>\n", referenceID)

	// QUERY store document on ORG1 (local)
	hash, err := ep1.StorePrivateDocument(ep1, ORG2.Name, referenceID, ExampleDocument.Payload)
	require.NoError(t, err)
	require.EqualValues(t, hash, ExampleDocument.PayloadHash)

	// readback should result in a payloadlink missing error
	_, err = ep1.FetchPrivateDocument(ep1, referenceID)
	require.Error(t, err)
	require.True(t, errorcode.PayloadLinkMissing.Matches(err))

	// publish reference payload link on the ledger
	referencePayloadLink, err := ep1.CreateReferencePayloadLink(ep1, referenceID, ExampleDocument.PayloadHash)
	require.NoError(t, err)
	referenceKey := referencePayloadLink[0]
	referenceValue := referencePayloadLink[1]
	err = ep1.InvokePublishReferencePayloadLink(ep1, referenceKey, referenceValue)
	require.NoError(t, err)

	// readback should now work
	dataJSON, err := ep1.FetchPrivateDocument(ep1, referenceID)
	require.NoError(t, err)

	// try to parse the data
	var data util.OffchainData
	err = json.Unmarshal([]byte(dataJSON), &data)
	require.NoError(t, err)

	require.EqualValues(t, data.FromMSP, "ORG1")
	require.EqualValues(t, data.ToMSP, "ORG2")
	require.EqualValues(t, data.Payload, ExampleDocument.Payload)
	require.EqualValues(t, data.PayloadHash, ExampleDocument.PayloadHash)
	require.EqualValues(t, data.ReferenceID, referenceID)

	require.EqualValues(t, data.BlockchainRef.Type, `hlf`)
	// todo: check those as well!
	// require.EqualValues(t, data.BlockchainRef.TxID, txID)
	// require.EqualValues(t, data.BlockchainRef.Timestamp, timestamp)

}

// publish a bad payloadlink and make sure we detect it
func TestStoreBadDocumentPayloadLink(t *testing.T) {
	// set up
	cleanupFunc, ep1, ep2 := setupTestCase(t)
	defer cleanupFunc(t)

	// calc referenceID
	referenceID, err := ep1.CreateReferenceID(ep2)
	require.NoError(t, err)
	log.Infof("got referenceID <%s>\n", referenceID)

	// QUERY store document on ORG1 (local)
	hash, err := ep1.StorePrivateDocument(ep1, ORG2.Name, referenceID, ExampleDocument.Payload)
	require.NoError(t, err)
	require.EqualValues(t, hash, ExampleDocument.PayloadHash)

	// publish a BAD reference payload link on the ledger
	referencePayloadLink, err := ep1.CreateReferencePayloadLink(ep1, referenceID, "bad")
	require.NoError(t, err)
	referenceKey := referencePayloadLink[0]
	referenceValue := referencePayloadLink[1]
	err = ep1.InvokePublishReferencePayloadLink(ep1, referenceKey, referenceValue)
	require.NoError(t, err)

	// readback should detect this bad payloadlink
	_, err = ep1.FetchPrivateDocument(ep1, referenceID)
	require.Error(t, err)
	require.True(t, errorcode.PayloadLinkInvalid.Matches(err))
}

func TestDocumentDelete(t *testing.T) {
	// set up
	cleanupFunc, ep1, ep2 := setupTestCase(t)
	defer cleanupFunc(t)

	// calc referenceID
	referenceID, err := ep1.CreateReferenceID(ep2)
	require.NoError(t, err)
	log.Infof("got docID <%s>\n", referenceID)

	// QUERY store document on ORG1 (local)
	hash, err := ep1.StorePrivateDocument(ep1, ORG2.Name, referenceID, ExampleDocument.Payload)
	require.NoError(t, err)
	require.EqualValues(t, hash, ExampleDocument.PayloadHash)

	// publish reference payload link on the ledger
	referencePayloadLink, err := ep1.CreateReferencePayloadLink(ep1, referenceID, ExampleDocument.PayloadHash)
	require.NoError(t, err)
	referenceKey := referencePayloadLink[0]
	referenceValue := referencePayloadLink[1]
	err = ep1.InvokePublishReferencePayloadLink(ep1, referenceKey, referenceValue)
	require.NoError(t, err)

	// VERIFY that it was written
	dataJSON, err := ep1.FetchPrivateDocument(ep1, referenceID)
	require.NoError(t, err)

	// VERIFY that the data store matches the uploaded data
	verifyData(t, dataJSON, &ExampleDocument)

	// VERIFY that its referenceId is returned as well
	ids, err := ep1.FetchPrivateDocumentReferenceIDs(ep1)
	require.NoError(t, err)
	require.EqualValues(t, `["`+referenceID+`"]`, ids)

	// delete
	err = ep1.DeletePrivateDocument(ep1, referenceID)
	require.NoError(t, err)

	// VERIFY that it was removed
	ids, err = ep1.FetchPrivateDocumentReferenceIDs(ep1)
	require.NoError(t, err)
	require.EqualValues(t, `[]`, ids)
}

func TestErrorHandling(t *testing.T) {
	// set up
	cleanupFunc, ep1, _ := setupTestCase(t)
	defer cleanupFunc(t)

	// calc referenceID
	_, err := ep1.CreateStorageKey(ep1, "targetMSP", "invalid_docid")
	require.Error(t, err)
	log.Infof("got error string as expected! (%s)\n", err.Error())

}

func TestSignatureValidation(t *testing.T) {
	// set up
	cleanupFunc, ep1, ep2 := setupTestCase(t)
	defer cleanupFunc(t)

	// calc referenceID
	referenceID, err := ep1.CreateReferenceID(ep1)
	require.NoError(t, err)
	log.Infof("got referenceId <%s>\n", referenceID)

	// skip the upload of the documents to both peers
	// here as they are not needed in this test

	// PUBLISH reference payload link on the ledger
	referencePayloadLink, err := ep1.CreateReferencePayloadLink(ep1, referenceID, ExampleDocument.PayloadHash)
	require.NoError(t, err)
	referenceKey := referencePayloadLink[0]
	referenceValue := referencePayloadLink[1]
	err = ep1.InvokePublishReferencePayloadLink(ep1, referenceKey, referenceValue)
	require.NoError(t, err)

	// ### org1 signs document:
	signaturePayload := chaincode.CreateSignaturePayload(ORG1.Name, referenceID, referenceValue)
	signature, err := chaincode.SignPayload(signaturePayload, ORG1.PrivateKey, ORG1.UserCertificate)
	require.NoError(t, err)

	// Validating signature
	err = ep1.IsValidSignature(ep2, ORG1.Name, signaturePayload, signature.Signature, signature.Certificate)
	require.NoError(t, err)
}

func TestFalseSignatureValidation(t *testing.T) {
	// set up
	cleanupFunc, ep1, ep2 := setupTestCase(t)
	defer cleanupFunc(t)

	// calc referenceID
	referenceID, err := ep1.CreateReferenceID(ep1)
	require.NoError(t, err)
	log.Infof("got referenceId <%s>\n", referenceID)

	// publish reference payload link on the ledger
	referencePayloadLink, err := ep1.CreateReferencePayloadLink(ep1, referenceID, ExampleDocument.PayloadHash)
	require.NoError(t, err)
	require.NoError(t, err)
	referenceKey := referencePayloadLink[0]
	referenceValue := referencePayloadLink[1]
	err = ep1.InvokePublishReferencePayloadLink(ep1, referenceKey, referenceValue)
	require.NoError(t, err)

	// ### org1 signs document using a bad cert:
	badCert := `-----BEGIN CERTIFICATE-----
MIICOTCCAb6gAwIBAgIUEfHHesjALbI1MxKLEPr2RhdxcMMwCgYIKoZIzj0EAwIw
YzESMBAGA1UEAwwJUk9PVEBPUkcxMQswCQYDVQQGEwJERTEMMAoGA1UECAwDTlJX
MRIwEAYDVQQHDAlCaWVsZWZlbGQxDTALBgNVBAoMBE9SRzExDzANBgNVBAsMBk9S
RzFPVTAeFw0yMDEyMTUxNTQ0MDRaFw0yMTEyMTUxNTQ0MDRaMGMxEjAQBgNVBAMM
CXVzZXJAT1JHMTELMAkGA1UEBhMCREUxDDAKBgNVBAgMA05SVzESMBAGA1UEBwwJ
QmllbGVmZWxkMQ0wCwYDVQQKDARPUkcxMQ8wDQYDVQQLDAZPUkcxT1UwdjAQBgcq
hkjOPQIBBgUrgQQAIgNiAATPVOccV+t57EDQQVTYqhjV+XNM0QlHUXb3K6RqmPNf
MlI+aHm6aNCzOna0iaIOaXLuEzsKBA8b8UdJ3QLS2cGadqwHGKehmAT3ughg2pcv
fKWGZ5kK7VKaaqxdCtKJg6+jMzAxMC8GCCoDBAUGBwgBBCN7ImF0dHJzIjp7IkNh
blNpZ25Eb2N1bWVudCI6InllcyJ9fTAKBggqhkjOPQQDAgNpADBmAjEAursYWIEP
lhx7sgedlY6X78lfsAvwwQe0uXj6JhioQIanYpUxDzpwPj/42Oq0rtgDAjEAu0De
fTAO/i0POc1ltcZ7QFY1GTYIaUOBGuYFDJambWQWh7jqcvZf42grSXQ0YvdB
-----END CERTIFICATE-----`
	signaturePayload := chaincode.CreateSignaturePayload(ORG1.Name, referenceID, referenceValue)
	signature, err := chaincode.SignPayload(signaturePayload, ORG1.PrivateKey, badCert)
	require.NoError(t, err)

	// Validating signature
	err = ep1.IsValidSignature(ep2, ORG1.Name, signaturePayload, signature.Signature, signature.Certificate)
	require.Error(t, err)
}
