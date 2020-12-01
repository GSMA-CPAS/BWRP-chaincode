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
	log "github.com/sirupsen/logrus"

	"github.com/stretchr/testify/require"
)

type EndpointMap map[*Organization]Endpoint

// Endpoint structure
type Endpoint struct {
	org       *Organization
	contract  *RoamingSmartContract
	txContext *mocks.TransactionContext
	stub      *historyshimtest.MockStub
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

func (local Endpoint) getSignatures(caller Endpoint, targetMSPID string, key string) (map[string]string, error) {
	log.Debugf("%s()", util.FunctionName())
	os.Setenv("CORE_PEER_LOCALMSPID", local.org.Name)
	return local.contract.GetSignatures(caller.txContext, targetMSPID, key)
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

func configureEndpoint(t *testing.T, mockStub *historyshimtest.MockStub, org Organization) Endpoint {
	var ep Endpoint
	ep.org = &org
	log.Infof(ep.org.Name + ": configuring endpoint, setting up db connection")

	// store mockstub
	ep.stub = mockStub

	// set up local msp id
	os.Setenv("CORE_PEER_LOCALMSPID", ep.org.Name)
	//start a couchdb dummy server to handle requests from chaincode
	couchdb.StartServer(ep.org.OffchainDBConfigURI)
	// init contract
	ep.contract = initRoamingSmartContract()

	// tx context
	txContext, err := chaincode.PrepareTransactionContext(ep.stub, ep.org.Name, ep.org.Certificate)
	require.NoError(t, err)

	// use context
	ep.txContext = txContext

	// set transient data for setting couchdb config
	var transient map[string][]byte
	transient = make(map[string][]byte)
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
	json.Unmarshal([]byte(data), &document)
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
	// create signature (later provided by external API/client)
	signatureORG1 := `{signer: "User1@ORG1", pem: "-----BEGIN CERTIFICATE--- ...", signature: "0x123..." }`
	// INVOKE storeSignature (here only org1, can also be all endorsers)
	err = ep1.invokeStoreSignature(ep1, storagekeyORG1, signatureORG1)
	require.NoError(t, err)

	// ### org2 signs document:
	// QUERY create storage key
	storagekeyORG2, err := ep2.createStorageKey(ep2, ORG2.Name, documentID)
	require.NoError(t, err)
	// create signature (later provided by external API/client)
	signatureORG2 := `{signer: "User1@ORG2", pem: "-----BEGIN CERTIFICATE--- ...", signature: "0x456..." }`

	// INVOKE storeSignature (here only org1, can also be all endorsers)
	err = ep1.invokeStoreSignature(ep2, storagekeyORG2, signatureORG2)
	require.NoError(t, err)

	// ### (optional) org1 checks signatures of org2 on document:
	// QUERY create expected key
	storagekeypartnerORG2, err := ep1.createStorageKey(ep1, ORG2.Name, documentID)
	require.Equal(t, storagekeyORG2, storagekeypartnerORG2)
	require.NoError(t, err)
	// QUERY GetSignatures
	signatures, err := ep1.getSignatures(ep1, ORG2.Name, storagekeypartnerORG2)
	require.NoError(t, err)
	chaincode.PrintSignatureResponse(signatures)

	// ### (optional) org2 checks signatures of org1 on document:
	// QUERY create expected key
	storagekeypartnerORG1, err := ep2.createStorageKey(ep2, ORG1.Name, documentID)
	require.NoError(t, err)
	// QUERY GetSignatures
	signatures, err = ep2.getSignatures(ep2, ORG1.Name, storagekeypartnerORG1)
	require.NoError(t, err)
	chaincode.PrintSignatureResponse(signatures)
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
}

func TestErrorHandling(t *testing.T) {
	log.Infof("################################################################################")
	log.Infof("running test " + util.FunctionName())
	log.Infof("################################################################################")

	// set up proper endpoints
	ep1, _ := createEndpoints(t)

	// calc documentID
	_, err := ep1.createStorageKey(ep1, "targetMSP", "invalid_docid")
	require.Error(t, err)
	log.Infof("got error string as expected! (%s)\n", err.Error())
}
