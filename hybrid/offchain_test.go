package main

//see https://github.com/hyperledger/fabric-samples/blob/master/asset-transfer-basic/chaincode-go/chaincode/smartcontract_test.go

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"hybrid/test/chaincode"
	. "hybrid/test/data"
	"hybrid/test/historyshimtest"
	"hybrid/test/mocks"
	"hybrid/test/rest"
	"os"
	"strconv"
	"testing"

	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

type EndpointMap map[*Organization]Endpoint

type Endpoint struct {
	org       *Organization
	contract  *RoamingSmartContract
	txContext *mocks.TransactionContext
	stub      *historyshimtest.MockStub
}

func createEndpoints(t *testing.T) EndpointMap {
	var endpoints EndpointMap
	endpoints = make(EndpointMap)

	// set loglevel
	log.SetLevel(log.InfoLevel)

	// set up stub
	mockStub := historyshimtest.NewMockStub("roamingState", nil)

	endpoints[&ORG1] = configureEndpoint(t, mockStub, ORG1)
	endpoints[&ORG2] = configureEndpoint(t, mockStub, ORG2)

	return endpoints
}

func configureEndpoint(t *testing.T, mockStub *historyshimtest.MockStub, org Organization) Endpoint {
	var ep Endpoint
	ep.org = &org
	log.Infof(ep.org.Name + ": configuring rest endpoint")

	// store mockstub
	ep.stub = mockStub

	// set up local msp id
	os.Setenv("CORE_PEER_LOCALMSPID", ep.org.Name)

	//start a simple rest servers to handle requests from chaincode
	rest.StartServer(ep.org.RestConfigPort)

	// init contract
	ep.contract = &RoamingSmartContract{}

	// tx context
	txContext, err := chaincode.PrepareTransactionContext(ep.stub, ep.org.Name, ep.org.Certificate)
	require.NoError(t, err)

	// use context
	ep.txContext = txContext

	// set transient data for setting rest config
	var transient map[string][]byte
	transient = make(map[string][]byte)
	targetURI := "http://localhost:" + strconv.Itoa(ep.org.RestConfigPort)
	transient["uri"] = []byte(targetURI)
	mockStub.TransientMap = transient
	err = ep.contract.SetRESTConfig(ep.txContext)
	require.NoError(t, err)

	// read back for debugging and testing
	uri, err := ep.contract.GetRESTConfig(ep.txContext)
	log.Infof(ep.org.Name+": read back uri <%s>\n", uri)
	require.NoError(t, err)
	require.EqualValues(t, uri, targetURI)

	return ep
}

// add forwarding functions
// those will make sure that the LOCALMSPID is always equal to the local organization
// and will additionally allow the calls to be executed in the caller's context
func (ep EndpointMap) storePrivateDocument(local *Organization, caller *Organization, targetMSPID string, documentID string, documentBase64 string) (string, error) {
	os.Setenv("CORE_PEER_LOCALMSPID", ep[local].org.Name)
	return ep[local].contract.StorePrivateDocument(ep[caller].txContext, targetMSPID, documentID, documentBase64)
}

func (ep EndpointMap) fetchPrivateDocument(local *Organization, caller *Organization, documentID string) (string, error) {
	os.Setenv("CORE_PEER_LOCALMSPID", ep[local].org.Name)
	return ep[local].contract.FetchPrivateDocument(ep[caller].txContext, documentID)
}

func (ep EndpointMap) fetchPrivateDocuments(local *Organization, caller *Organization) (string, error) {
	os.Setenv("CORE_PEER_LOCALMSPID", ep[local].org.Name)
	return ep[local].contract.FetchPrivateDocuments(ep[caller].txContext)
}

func (ep EndpointMap) createStorageKey(local *Organization, caller *Organization, targetMSPID string, documentID string) (string, error) {
	os.Setenv("CORE_PEER_LOCALMSPID", ep[local].org.Name)
	return ep[local].contract.CreateStorageKey(targetMSPID, documentID) // TODO: no tx context in this func?!
}

func (ep EndpointMap) getDocumentID(local *Organization, caller *Organization, storageKey string) (string, error) {
	os.Setenv("CORE_PEER_LOCALMSPID", ep[local].org.Name)
	return ep[local].contract.GetDocumentID(ep[caller].txContext, storageKey)
}

func (ep EndpointMap) getRESTConfig(local *Organization, caller *Organization) (string, error) {
	os.Setenv("CORE_PEER_LOCALMSPID", ep[local].org.Name)
	return ep[local].contract.GetRESTConfig(ep[caller].txContext)
}

func (ep EndpointMap) createDocumentID(local *Organization, caller *Organization) (string, error) {
	os.Setenv("CORE_PEER_LOCALMSPID", ep[local].org.Name)
	return ep[local].contract.CreateDocumentID(ep[caller].txContext)
}

func (ep EndpointMap) getSignatures(local *Organization, caller *Organization, targetMSPID string, key string) (map[string]string, error) {
	os.Setenv("CORE_PEER_LOCALMSPID", ep[local].org.Name)
	return ep[local].contract.GetSignatures(ep[caller].txContext, targetMSPID, key)
}

func (ep EndpointMap) invokeStoreDocumentHash(local *Organization, caller *Organization, key string, documentHash string) error {
	txid := local.Name + ":" + uuid.New().String()
	ep[local].stub.MockTransactionStart(txid)
	os.Setenv("CORE_PEER_LOCALMSPID", ep[local].org.Name)
	err := ep[local].contract.StoreDocumentHash(ep[caller].txContext, key, documentHash)
	ep[local].stub.MockTransactionEnd(txid)
	return err
}

func (ep EndpointMap) invokeStoreSignature(local *Organization, caller *Organization, key string, signatureJSON string) error {
	txid := local.Name + ":" + uuid.New().String()
	ep[local].stub.MockTransactionStart(txid)
	os.Setenv("CORE_PEER_LOCALMSPID", ep[local].org.Name)
	err := ep[local].contract.StoreSignature(ep[caller].txContext, key, signatureJSON)
	ep[local].stub.MockTransactionEnd(txid)
	return err
}

func TestPrivateDocumentAccess(t *testing.T) {
	// set up proper endpoints
	ep := createEndpoints(t)

	// read private documents on ORG1 with ORG1 tx context
	response, err := ep.fetchPrivateDocuments(&ORG1, &ORG1)
	require.NoError(t, err)
	log.Info(response)

	// read private documents on ORG1 with ORG2 tx context
	response, err = ep.fetchPrivateDocuments(&ORG1, &ORG2)
	require.Error(t, err)
	log.Info(response)
}

func TestRestConfig(t *testing.T) {
	log.Infof("testing REST")
	// set up proper endpoints
	ep := createEndpoints(t)

	// read back for debugging
	// note that this is not allowed on chaincode calls
	// as getRESTConfig is not exported
	os.Setenv("CORE_PEER_LOCALMSPID", ORG1.Name)
	uri, err := contractORG1.GetRESTConfig(txContextORG1)
	log.Infof("read back uri <%s>\n", uri)
	require.NoError(t, err)
	log.Infof("read back uri <%s>\n", uri)

	// read back with txcontext ORG2 -> this has to fail!
	_, err = ep.getRESTConfig(&ORG1, &ORG2)
	require.Error(t, err)
}

func TestExchangeAndSigning(t *testing.T) {
	// set up proper endpoints
	ep := createEndpoints(t)

	// calc documentID
	documentID, err := ep.createDocumentID(&ORG1, &ORG1)
	require.NoError(t, err)
	log.Infof("got docID <%s>\n", documentID)

	// QUERY store document on ORG1 (local)
	hash, err := ep.storePrivateDocument(&ORG1, &ORG1, ORG2.Name, documentID, ExampleDocument.Data64)
	require.NoError(t, err)
	require.EqualValues(t, hash, ExampleDocument.Hash)

	// VERIFY that it was written
	data, err := ep.fetchPrivateDocument(&ORG1, &ORG1, documentID)
	require.NoError(t, err)

	// TODO: check all attributes...
	var document map[string]interface{}
	json.Unmarshal([]byte(data), &document)
	require.EqualValues(t, document["data"], ExampleDocument.Data64)

	// QUERY store document on ORG2 (remote)
	hash, err = ep.storePrivateDocument(&ORG2, &ORG1, ORG2.Name, documentID, ExampleDocument.Data64)
	require.NoError(t, err)
	require.EqualValues(t, hash, ExampleDocument.Hash)

	// QUERY create storage key
	storagekeyORG1, err := ep.createStorageKey(&ORG1, &ORG1, ORG1.Name, documentID)
	require.NoError(t, err)

	// upload document hash on the ledger
	err = ep.invokeStoreDocumentHash(&ORG1, &ORG1, storagekeyORG1, ExampleDocument.Hash)
	require.NoError(t, err)

	// ### org1 signs document:
	// create signature (later provided by external API/client)
	signatureORG1 := `{signer: "User1@ORG1", pem: "-----BEGIN CERTIFICATE--- ...", signature: "0x123..." }`
	// INVOKE storeSignature (here only org1, can also be all endorsers)
	err = ep.invokeStoreSignature(&ORG1, &ORG1, storagekeyORG1, signatureORG1)
	require.NoError(t, err)

	// ### org2 signs document:
	// QUERY create storage key
	storagekeyORG2, err := ep.createStorageKey(&ORG2, &ORG2, ORG2.Name, documentID)
	require.NoError(t, err)
	// create signature (later provided by external API/client)
	signatureORG2 := `{signer: "User1@ORG2", pem: "-----BEGIN CERTIFICATE--- ...", signature: "0x456..." }`

	// INVOKE storeSignature (here only org1, can also be all endorsers)
	err = ep.invokeStoreSignature(&ORG1, &ORG2, storagekeyORG2, signatureORG2)
	require.NoError(t, err)

	// ### (optional) org1 checks signatures of org2 on document:
	// QUERY create expected key
	storagekeypartnerORG2, err := ep[&ORG1].contract.CreateStorageKey(ORG2.Name, documentID)
	require.Equal(t, storagekeyORG2, storagekeypartnerORG2)
	require.NoError(t, err)
	// QUERY GetSignatures
	signatures, err := ep.getSignatures(&ORG1, &ORG1, ORG2.Name, storagekeypartnerORG2)
	require.NoError(t, err)
	chaincode.PrintSignatureResponse(signatures)

	// ### (optional) org2 checks signatures of org1 on document:
	// QUERY create expected key
	storagekeypartnerORG1, err := ep[&ORG2].contract.CreateStorageKey(ORG1.Name, documentID)
	require.NoError(t, err)
	// QUERY GetSignatures
	signatures, err = ep.getSignatures(&ORG2, &ORG2, ORG1.Name, storagekeypartnerORG1)
	require.NoError(t, err)
	chaincode.PrintSignatureResponse(signatures)
}

// Test GetDocumentID storagekeyORG1
func TestGetDocumentID(t *testing.T) {
	// set up proper endpoints
	ep := createEndpoints(t)

	// ### Org1 creates a document and sends it to Org2:
	// a test document:
	documentBase64 := base64.StdEncoding.EncodeToString([]byte(`data!1234...`))

	// calc data hash
	tmp := sha256.Sum256([]byte(documentBase64))
	dataHash := hex.EncodeToString(tmp[:])

	// calc documentID
	documentID, err := ep[&ORG1].contract.CreateDocumentID(ep[&ORG1].txContext)
	require.NoError(t, err)
	log.Infof("got docID <%s>\n", documentID)

	// QUERY store document on ORG1 (local)
	hash, err := ep.storePrivateDocument(&ORG1, &ORG1, ORG2.Name, documentID, documentBase64)
	require.NoError(t, err)
	require.EqualValues(t, hash, dataHash)

	// QUERY create storage key
	storagekeyORG1, err := ep.createStorageKey(&ORG1, &ORG1, ORG1.Name, documentID)
	require.NoError(t, err)

	// ### (optional) org2 checks signatures of org1 on document:
	// QUERY create expected key
	response, err := ep.getDocumentID(&ORG1, &ORG1, storagekeyORG1)
	require.NoError(t, err)
	var responseJSON map[string]interface{}
	log.Infof(response)
	err = json.Unmarshal([]byte(response), &responseJSON)
	require.NoError(t, err)
	require.EqualValues(t, responseJSON["documentID"].(string), documentID)

}
