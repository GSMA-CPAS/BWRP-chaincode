package main

//see https://github.com/hyperledger/fabric-samples/blob/master/asset-transfer-basic/chaincode-go/chaincode/smartcontract_test.go

import (
	"encoding/json"
	"hybrid/test/chaincode"
	couchdb "hybrid/test/couchdb_dummy"
	. "hybrid/test/data"
	"hybrid/test/historyshimtest"
	"hybrid/test/mocks"
	"hybrid/util"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	log "github.com/sirupsen/logrus"

	"github.com/stretchr/testify/require"
)

// Endpoint structure
type Endpoint struct {
	org       *Organization
	contract  *RoamingSmartContract
	txContext *mocks.TransactionContext
	stub      *historyshimtest.MockStub
	couchdb   *echo.Echo
}

// add forwarding functions
// those will make sure that the LOCALMSPID is always equal to the local organization
// and will additionally allow the calls to be executed in the caller's context
func (local Endpoint) storePrivateDocument(caller Endpoint, targetMSPID string, documentID string, documentBase64 string) (string, error) {
	log.Debugf("%s()", util.FunctionName())
	os.Setenv("CORE_PEER_LOCALMSPID", local.org.Name)
	return local.contract.StorePrivateDocument(caller.txContext, targetMSPID, documentID, documentBase64)
}

func (local Endpoint) fetchPrivateDocument(caller Endpoint, documentID string) (string, error) {
	log.Debugf("%s()", util.FunctionName())
	os.Setenv("CORE_PEER_LOCALMSPID", local.org.Name)
	return local.contract.FetchPrivateDocument(caller.txContext, documentID)
}

func (local Endpoint) deletePrivateDocument(caller Endpoint, documentID string) error {
	log.Debugf("%s()", util.FunctionName())
	os.Setenv("CORE_PEER_LOCALMSPID", local.org.Name)
	return local.contract.DeletePrivateDocument(caller.txContext, documentID)
}

func (local Endpoint) fetchPrivateDocumentIDs(caller Endpoint) (string, error) {
	log.Debugf("%s()", util.FunctionName())
	os.Setenv("CORE_PEER_LOCALMSPID", local.org.Name)
	return local.contract.FetchPrivateDocumentIDs(caller.txContext)
}

func (local Endpoint) createStorageKey(caller Endpoint, targetMSPID string, documentID string) (string, error) {
	log.Debugf("%s()", util.FunctionName())
	os.Setenv("CORE_PEER_LOCALMSPID", local.org.Name)
	return local.contract.CreateStorageKey(targetMSPID, documentID) // TODO: no tx context in this func?!
}

func (local Endpoint) getOffchainDBConfig(caller Endpoint) (string, error) {
	log.Debugf("%s()", util.FunctionName())
	os.Setenv("CORE_PEER_LOCALMSPID", local.org.Name)
	return local.contract.GetOffchainDBConfig(caller.txContext)
}

func (local Endpoint) createDocumentID(caller Endpoint) (string, error) {
	log.Debugf("%s()", util.FunctionName())
	os.Setenv("CORE_PEER_LOCALMSPID", local.org.Name)
	return local.contract.CreateDocumentID(caller.txContext)
}

func (local Endpoint) getSignatures(caller Endpoint, targetMSPID string, documentID string) (map[string]string, error) {
	log.Debugf("%s()", util.FunctionName())
	os.Setenv("CORE_PEER_LOCALMSPID", local.org.Name)
	return local.contract.GetSignatures(caller.txContext, targetMSPID, documentID)
}

func (local Endpoint) verifySignatures(caller Endpoint, targetMSPID string, documentID string, document string) (map[string]map[string]string, error) {
	log.Debugf("%s()", util.FunctionName())
	os.Setenv("CORE_PEER_LOCALMSPID", local.org.Name)
	return local.contract.VerifySignatures(caller.txContext, targetMSPID, documentID, document)
}

func (local Endpoint) isSignatureValid(caller Endpoint, msp string, document string, signature string, certListStr string) error {
	log.Debugf("%s()", util.FunctionName())
	os.Setenv("CORE_PEER_LOCALMSPID", local.org.Name)
	return local.contract.IsValidSignature(caller.txContext, msp, document, signature, certListStr)
}

func (local Endpoint) invokeSetCertificate(caller Endpoint, certType string, certData string) error {
	log.Debugf("%s()", util.FunctionName())
	txid := local.org.Name + ":" + uuid.New().String()
	local.stub.MockTransactionStart(txid)
	os.Setenv("CORE_PEER_LOCALMSPID", local.org.Name)
	err := local.contract.SetCertificate(caller.txContext, certType, certData)
	local.stub.MockTransactionEnd(txid)
	return err
}

func (local Endpoint) invokeStoreDocumentHash(caller Endpoint, key string, documentHash string) error {
	log.Debugf("%s()", util.FunctionName())
	txid := local.org.Name + ":" + uuid.New().String()
	local.stub.MockTransactionStart(txid)
	os.Setenv("CORE_PEER_LOCALMSPID", local.org.Name)
	err := local.contract.StoreDocumentHash(caller.txContext, key, documentHash)
	local.stub.MockTransactionEnd(txid)
	return err
}

func (local Endpoint) invokeStoreSignature(caller Endpoint, key string, signatureJSON string) error {
	log.Debugf("%s()", util.FunctionName())
	txid := local.org.Name + ":" + uuid.New().String()
	local.stub.MockTransactionStart(txid)
	os.Setenv("CORE_PEER_LOCALMSPID", local.org.Name)
	err := local.contract.StoreSignature(caller.txContext, key, signatureJSON)
	local.stub.MockTransactionEnd(txid)
	return err
}

func createEndpoints(t *testing.T) (Endpoint, Endpoint) {
	// set loglevel
	//log.SetLevel(log.InfoLevel)
	log.SetLevel(log.DebugLevel)

	// set up stub
	mockStub := historyshimtest.NewMockStub("roamingState", nil)

	epORG1 := configureEndpoint(t, mockStub, ORG1)
	epORG2 := configureEndpoint(t, mockStub, ORG2)

	return epORG1, epORG2
}

func closeEndpoints(ep1 Endpoint, ep2 Endpoint) {
	ep1.couchdb.Close()
	ep2.couchdb.Close()
}

func configureEndpoint(t *testing.T, mockStub *historyshimtest.MockStub, org Organization) Endpoint {
	var ep Endpoint
	ep.org = &org
	log.Infof(ep.org.Name + ": configuring endpoint, setting up db connection")

	// store mockstub
	ep.stub = mockStub

	// set up local msp id
	os.Setenv("CORE_PEER_LOCALMSPID", ep.org.Name)
	//start a couchdb dummy server to handle requests from chaincode
	ep.couchdb = couchdb.StartServer(ep.org.OffchainDBConfigURI)
	// init contract
	ep.contract = initRoamingSmartContract()

	// tx context
	txContext, err := chaincode.PrepareTransactionContext(ep.stub, ep.org.Name, ep.org.UserCertificate)
	require.NoError(t, err)

	// use context
	ep.txContext = txContext

	// set transient data for setting couchdb config
	var transient map[string][]byte = make(map[string][]byte)
	url := "http://" + ep.org.OffchainDBConfigURI
	transient["uri"] = []byte(url)
	mockStub.TransientMap = transient
	err = ep.contract.SetOffchainDBConfig(ep.txContext)
	require.NoError(t, err)

	// read back for debugging and testing
	uri, err := ep.contract.GetOffchainDBConfig(ep.txContext)
	log.Infof(ep.org.Name+": read back uri <%s>\n", uri)
	require.NoError(t, err)
	require.EqualValues(t, uri, url)

	// store root cert:
	err = ep.invokeSetCertificate(ep, "root", string(ep.org.RootCertificate))
	require.NoError(t, err)

	return ep
}

func TestPrivateDocumentAccess(t *testing.T) {
	log.Infof("################################################################################")
	log.Infof("running test " + util.FunctionName())
	log.Infof("################################################################################")

	// set up proper endpoints
	ep1, ep2 := createEndpoints(t)

	// read private documents on ORG1 with ORG1 tx context
	response, err := ep1.fetchPrivateDocumentIDs(ep1)
	require.NoError(t, err)
	log.Info(response)

	// read private documents on ORG1 with ORG2 tx context
	response, err = ep1.fetchPrivateDocumentIDs(ep2)
	require.Error(t, err)
	log.Info(response)

	// shut down dummy db
	closeEndpoints(ep1, ep2)
}

func TestOffchainDBConfig(t *testing.T) {
	log.Infof("################################################################################")
	log.Infof("running test " + util.FunctionName())
	log.Infof("################################################################################")

	// set up proper endpoints
	ep1, ep2 := createEndpoints(t)

	// read back for debugging
	// note that this is not allowed on chaincode calls
	// as getOffchainDBConfig is not exported
	os.Setenv("CORE_PEER_LOCALMSPID", ORG1.Name)
	uri, err := ep1.getOffchainDBConfig(ep1)
	require.NoError(t, err)
	log.Infof("read back uri <%s>\n", uri)

	// read back with txcontext ORG2 -> this has to fail!
	_, err = ep1.getOffchainDBConfig(ep2)
	require.Error(t, err)

	// shut down dummy db
	closeEndpoints(ep1, ep2)
}

func TestExchangeAndSigning(t *testing.T) {
	log.Infof("################################################################################")
	log.Infof("running test " + util.FunctionName())
	log.Infof("################################################################################")

	// set up proper endpoints
	ep1, ep2 := createEndpoints(t)

	// calc documentID
	documentID, err := ep1.createDocumentID(ep2)
	require.NoError(t, err)
	log.Infof("got docID <%s>\n", documentID)

	// QUERY store document on ORG1 (local)
	hash, err := ep1.storePrivateDocument(ep1, ORG2.Name, documentID, ExampleDocument.Data64)
	require.NoError(t, err)
	require.EqualValues(t, hash, ExampleDocument.Hash)

	// VERIFY that it was written
	data, err := ep1.fetchPrivateDocument(ep1, documentID)
	require.NoError(t, err)

	// just for testing, check all stored doc ids:
	response, err := ep1.fetchPrivateDocumentIDs(ep1)
	require.NoError(t, err)
	log.Info(response)

	// TODO: check all attributes...
	var document map[string]interface{}
	err = json.Unmarshal([]byte(data), &document)
	require.NoError(t, err)
	require.EqualValues(t, document["data"], ExampleDocument.Data64)

	// QUERY store document on ORG2 (remote)
	hash, err = ep2.storePrivateDocument(ep1, ORG2.Name, documentID, ExampleDocument.Data64)
	require.NoError(t, err)
	require.EqualValues(t, hash, ExampleDocument.Hash)

	// QUERY create storage key
	storagekeyORG1, err := ep1.createStorageKey(ep1, ORG1.Name, documentID)
	require.NoError(t, err)

	// upload document hash on the ledger
	err = ep1.invokeStoreDocumentHash(ep1, storagekeyORG1, ExampleDocument.Hash)
	require.NoError(t, err)

	// ### org1 signs document:
	signature, err := chaincode.SignDocument(ExampleDocument.Data64, ORG1.PrivateKey, ORG1.UserCertificate)
	require.NoError(t, err)
	signatureJSON, err := json.Marshal(signature)
	require.NoError(t, err)

	// INVOKE storeSignature (here only org1, can also be all endorsers)
	err = ep1.invokeStoreSignature(ep1, storagekeyORG1, string(signatureJSON))
	require.NoError(t, err)

	// ### org2 signs document:
	// QUERY create storage key
	storagekeyORG2, err := ep2.createStorageKey(ep2, ORG2.Name, documentID)
	require.NoError(t, err)

	// create document signature
	signature, err = chaincode.SignDocument(ExampleDocument.Data64, ORG2.PrivateKey, ORG2.UserCertificate)
	require.NoError(t, err)
	signatureJSON, err = json.Marshal(signature)
	require.NoError(t, err)

	// INVOKE storeSignature (here only org1, can also be all endorsers)
	err = ep1.invokeStoreSignature(ep2, storagekeyORG2, string(signatureJSON))
	require.NoError(t, err)

	// ### (optional) org1 checks signatures of org2 on document:
	// QUERY create expected key
	storagekeypartnerORG2, err := ep1.createStorageKey(ep1, ORG2.Name, documentID)
	require.Equal(t, storagekeyORG2, storagekeypartnerORG2)
	require.NoError(t, err)

	// QUERY GetSignatures
	signatures, err := ep1.getSignatures(ep1, ORG2.Name, documentID)
	require.NoError(t, err)
	chaincode.PrintSignatureResponse(signatures)

	// ### (optional) org2 checks signatures of org1 on document:
	// QUERY GetSignatures
	signatures, err = ep2.getSignatures(ep2, ORG1.Name, documentID)
	require.NoError(t, err)
	chaincode.PrintSignatureResponse(signatures)

	// QUERY verify signatures on ORG1
	verification, err := ep2.verifySignatures(ep2, ORG1.Name, documentID, ExampleDocument.Data64)
	require.NoError(t, err)
	err = chaincode.CheckSignatureResponse(verification)
	require.NoError(t, err)

	// QUERY verify signatures on ORG2
	verification, err = ep2.verifySignatures(ep2, ORG2.Name, documentID, ExampleDocument.Data64)
	require.NoError(t, err)
	err = chaincode.CheckSignatureResponse(verification)
	require.NoError(t, err)

	// shut down dummy db
	closeEndpoints(ep1, ep2)
}

func TestDocumentDelete(t *testing.T) {
	log.Infof("################################################################################")
	log.Infof("running test " + util.FunctionName())
	log.Infof("################################################################################")

	// set up proper endpoints
	ep1, ep2 := createEndpoints(t)

	// calc documentID
	documentID, err := ep1.createDocumentID(ep2)
	require.NoError(t, err)
	log.Infof("got docID <%s>\n", documentID)

	// QUERY store document on ORG1 (local)
	hash, err := ep1.storePrivateDocument(ep1, ORG2.Name, documentID, ExampleDocument.Data64)
	require.NoError(t, err)
	require.EqualValues(t, hash, ExampleDocument.Hash)

	// VERIFY that it was written
	ids, err := ep1.fetchPrivateDocumentIDs(ep1)
	require.NoError(t, err)
	require.EqualValues(t, `["`+documentID+`"]`, ids)

	// delete
	err = ep1.deletePrivateDocument(ep1, documentID)
	require.NoError(t, err)

	// VERIFY that it was removed
	ids, err = ep1.fetchPrivateDocumentIDs(ep1)
	require.NoError(t, err)
	require.EqualValues(t, `[]`, ids)

	// shut down dummy db
	closeEndpoints(ep1, ep2)
}

func TestErrorHandling(t *testing.T) {
	log.Infof("################################################################################")
	log.Infof("running test " + util.FunctionName())
	log.Infof("################################################################################")

	// set up proper endpoints
	ep1, ep2 := createEndpoints(t)

	// calc documentID
	_, err := ep1.createStorageKey(ep1, "targetMSP", "invalid_docid")
	require.Error(t, err)
	log.Infof("got error string as expected! (%s)\n", err.Error())

	// shut down dummy db
	closeEndpoints(ep1, ep2)
}

func TestSignatureValidation(t *testing.T) {
	log.Infof("################################################################################")
	log.Infof("running test " + util.FunctionName())
	log.Infof("################################################################################")

	// set up proper endpoints
	ep1, ep2 := createEndpoints(t)

	// ### org1 signs document:
	signature, err := chaincode.SignDocument(ExampleDocument.Data64, ORG1.PrivateKey, ORG1.UserCertificate)
	require.NoError(t, err)

	// Validating signature
	err = ep1.isSignatureValid(ep2, ORG1.Name, ExampleDocument.Data64, signature.Signature, signature.Certificate)
	require.NoError(t, err)

	// shut down dummy db
	closeEndpoints(ep1, ep2)
}

func TestFalseSignatureValidation(t *testing.T) {
	log.Infof("################################################################################")
	log.Infof("running test " + util.FunctionName())
	log.Infof("################################################################################")

	// set up proper endpoints
	ep1, ep2 := createEndpoints(t)

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
	signature, err := chaincode.SignDocument(ExampleDocument.Data64, ORG1.PrivateKey, badCert)
	require.NoError(t, err)

	// Validating signature
	err = ep1.isSignatureValid(ep2, ORG1.Name, ExampleDocument.Data64, signature.Signature, signature.Certificate)
	require.Error(t, err)
	log.Infof("got error as expected! (%s)\n", err.Error())

	// shut down dummy db
	closeEndpoints(ep1, ep2)
}
