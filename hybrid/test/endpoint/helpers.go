package endpoint

import (
	"hybrid/contract"
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
	contract  *contract.RoamingSmartContract
	txContext *mocks.TransactionContext
	stub      *historyshimtest.MockStub
	couchdb   *echo.Echo
}

// add forwarding functions
// those will make sure that the LOCALMSPID is always equal to the local organization
// and will additionally allow the calls to be executed in the caller's context
func (local Endpoint) StorePrivateDocument(caller Endpoint, targetMSPID string, referenceID string, payloadHash string) (string, error) {
	log.Debugf("%s()", util.FunctionName(1))
	os.Setenv("CORE_PEER_LOCALMSPID", local.org.Name)
	return local.contract.StorePrivateDocument(caller.txContext, targetMSPID, referenceID, payloadHash)
}

func (local Endpoint) FetchPrivateDocument(caller Endpoint, referenceID string) (string, error) {
	log.Debugf("%s()", util.FunctionName(1))
	os.Setenv("CORE_PEER_LOCALMSPID", local.org.Name)
	return local.contract.FetchPrivateDocument(caller.txContext, referenceID)
}

func (local Endpoint) DeletePrivateDocument(caller Endpoint, referenceID string) error {
	log.Debugf("%s()", util.FunctionName(1))
	os.Setenv("CORE_PEER_LOCALMSPID", local.org.Name)
	return local.contract.DeletePrivateDocument(caller.txContext, referenceID)
}

func (local Endpoint) FetchPrivateDocumentReferenceIDs(caller Endpoint) (string, error) {
	log.Debugf("%s()", util.FunctionName(1))
	os.Setenv("CORE_PEER_LOCALMSPID", local.org.Name)
	return local.contract.FetchPrivateDocumentReferenceIDs(caller.txContext)
}

func (local Endpoint) CreateStorageKey(caller Endpoint, targetMSPID string, referenceID string) (string, error) {
	log.Debugf("%s()", util.FunctionName(1))
	log.Debugf("%s", referenceID)
	os.Setenv("CORE_PEER_LOCALMSPID", local.org.Name)
	return local.contract.CreateStorageKey(targetMSPID, referenceID) // TODO: no tx context in this func?!
}

func (local Endpoint) CreateReferenceID(caller Endpoint) (string, error) {
	log.Debugf("%s()", util.FunctionName(1))
	os.Setenv("CORE_PEER_LOCALMSPID", local.org.Name)
	return local.contract.CreateReferenceID(caller.txContext)
}

func (local Endpoint) CreateReferencePayloadLink(caller Endpoint, referenceID string, payloadHash string) ([2]string, error) {
	log.Debugf("%s()", util.FunctionName(1))
	os.Setenv("CORE_PEER_LOCALMSPID", local.org.Name)
	return local.contract.CreateReferencePayloadLink(referenceID, payloadHash)
}

func (local Endpoint) GetOffchainDBConfig(caller Endpoint) (string, error) {
	log.Debugf("%s()", util.FunctionName(1))
	os.Setenv("CORE_PEER_LOCALMSPID", local.org.Name)
	return local.contract.GetOffchainDBConfig(caller.txContext)
}

/*func (local Endpoint) getReferencePayloadLink(caller Endpoint, creatorMSPID string, referenceID string) (string, error) {
	log.Debugf("%s()", util.FunctionName(1))
	os.Setenv("CORE_PEER_LOCALMSPID", local.org.Name)
	return local.contract.GetReferencePayloadLink(caller.txContext, creatorMSPID, referenceID)
}*/

func (local Endpoint) GetSignatures(caller Endpoint, targetMSPID string, key string) (map[string]string, error) {
	log.Debugf("%s()", util.FunctionName(1))
	os.Setenv("CORE_PEER_LOCALMSPID", local.org.Name)
	return local.contract.GetSignatures(caller.txContext, targetMSPID, key)
}

func (local Endpoint) IsValidSignature(caller Endpoint, creatorMSP string, document string, signature string, certListStr string) error {
	log.Debugf("%s()", util.FunctionName(1))
	os.Setenv("CORE_PEER_LOCALMSPID", local.org.Name)
	return local.contract.IsValidSignature(caller.txContext, creatorMSP, document, signature, certListStr)
}

func (local Endpoint) VerifySignatures(caller Endpoint, referenceID string, originMSPID string, targetMSPID string) (map[string]map[string]string, error) {
	log.Debugf("%s()", util.FunctionName(1))
	os.Setenv("CORE_PEER_LOCALMSPID", local.org.Name)
	return local.contract.VerifySignatures(caller.txContext, referenceID, originMSPID, targetMSPID)
}

func (local Endpoint) InvokeSetCertificate(caller Endpoint, certType string, certData string) error {
	log.Debugf("%s()", util.FunctionName(1))
	txid := local.org.Name + ":" + uuid.New().String()
	local.stub.MockTransactionStart(txid)
	os.Setenv("CORE_PEER_LOCALMSPID", local.org.Name)
	err := local.contract.SetCertificate(caller.txContext, certType, certData)
	local.stub.MockTransactionEnd(txid)
	return err
}

func (local Endpoint) InvokePublishReferencePayloadLink(caller Endpoint, key string, value string) error {
	log.Debugf("%s()", util.FunctionName(1))
	txid := local.org.Name + ":" + uuid.New().String()
	local.stub.MockTransactionStart(txid)
	os.Setenv("CORE_PEER_LOCALMSPID", local.org.Name)
	_, err := local.contract.PublishReferencePayloadLink(caller.txContext, key, value)
	local.stub.MockTransactionEnd(txid)
	return err
}

func (local Endpoint) InvokeStoreSignature(caller Endpoint, key string, signatureJSON string) error {
	log.Debugf("%s()", util.FunctionName(1))
	txid := local.org.Name + ":" + uuid.New().String()
	local.stub.MockTransactionStart(txid)
	os.Setenv("CORE_PEER_LOCALMSPID", local.org.Name)
	_, err := local.contract.StoreSignature(caller.txContext, key, signatureJSON)
	local.stub.MockTransactionEnd(txid)
	return err
}

func CreateEndpoints(t *testing.T) (Endpoint, Endpoint) {
	// set loglevel
	//log.SetLevel(log.InfoLevel)
	log.SetLevel(log.DebugLevel)

	// set up stub
	mockStub := historyshimtest.NewMockStub("roamingState", nil)

	epORG1 := ConfigureEndpoint(t, mockStub, ORG1)
	epORG2 := ConfigureEndpoint(t, mockStub, ORG2)

	return epORG1, epORG2
}

func (ep *Endpoint) Close() {
	ep.couchdb.Close()
}

func ConfigureEndpoint(t *testing.T, mockStub *historyshimtest.MockStub, org Organization) Endpoint {
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
	ep.contract = contract.InitRoamingSmartContract()

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
	err = ep.InvokeSetCertificate(ep, "root", string(ep.org.RootCertificate))
	require.NoError(t, err)
	return ep
}
