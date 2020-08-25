package offchain

//see https://github.com/hyperledger/fabric-samples/blob/master/asset-transfer-basic/chaincode-go/chaincode/smartcontract_test.go

import (
	"chaincode/offchain_rest/historyshimtest"
	"chaincode/offchain_rest/mocks"
	"encoding/base64"
	"fmt"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric-chaincode-go/pkg/cid"
	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-contract-api-go/contractapi"
	"github.com/hyperledger/fabric-protos-go/msp"
	"github.com/labstack/echo/v4"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

//go:generate counterfeiter -o mocks/chaincodestub.go -fake-name ChaincodeStub . chaincodeStub
type chaincodeStub interface {
	shim.ChaincodeStubInterface
}

//go:generate counterfeiter -o mocks/transaction.go -fake-name TransactionContext . transactionContext
type transactionContext interface {
	contractapi.TransactionContextInterface
}

func createIdentity(mspID string, idbytes []byte) ([]byte, error) {
	sid := &msp.SerializedIdentity{Mspid: mspID, IdBytes: idbytes}
	b, err := proto.Marshal(sid)
	return b, err
}

func prepareTransactionContext(stub *historyshimtest.MockStub, orgmsp string, cert []byte) (*mocks.TransactionContext, error) {
	creator, err := createIdentity(orgmsp, cert)
	stub.Creator = creator

	if err != nil {
		return nil, err
	}

	clientID, err := cid.New(stub)
	if err != nil {
		return nil, err
	}

	// tell the mock setup what to return
	transactionContext := &mocks.TransactionContext{}
	transactionContext.GetStubReturns(stub)
	transactionContext.GetClientIdentityReturns(clientID)

	return transactionContext, nil
}

func showRestData(c echo.Context) error {
	log.Infof("on %s got: %s", c.Echo().Server.Addr, c.Request().URL)
	return c.String(http.StatusOK, "Print OK")
}

func startRestServer(port int) {
	e := echo.New()

	// define routes
	e.POST("/write/*", showRestData)

	// start server
	url := ":" + strconv.Itoa(port)
	log.Info("will listen on " + url)
	go func() {
		err := e.Start(url)
		if err != nil {
			log.Panic(err)
		}
	}()
	time.Sleep(200 * time.Millisecond)
}

func printSignatureResponse(input map[string][]byte) {
	for identity, signature := range input {
		iddecoded, _ := base64.StdEncoding.DecodeString(identity)
		fmt.Printf("identity: %s => signature: %s", iddecoded, signature)
	}
}

func TestExchangeAndSigning(t *testing.T) {
	//start two simple rest servers to handle requests from chaincode
	startRestServer(3001) //ORG1
	startRestServer(3002) //ORG2

	// init contracts according to the above rest servers
	contractORG1 := RoamingSmartContract{restURI: "http://localhost:3001"}
	contractORG2 := RoamingSmartContract{restURI: "http://localhost:3002"}

	// create internal state map
	mockStub := historyshimtest.NewMockStub("roamingState", nil)

	// ### Org1 creates a document and sends it to Org2:
	// a binary test document:
	document := []byte(`data!1234...`)

	// ORG1 as "sender"
	txContextORG1, err := prepareTransactionContext(mockStub, ORG1.Name, ORG1.Certificate)
	require.NoError(t, err)
	// ORG2 as "receiver" and later signer
	txContextORG2, err := prepareTransactionContext(mockStub, ORG2.Name, ORG2.Certificate)
	require.NoError(t, err)

	// QUERY store document on ORG1 (local)
	err = contractORG1.StorePrivateDocument(txContextORG1, ORG2.Name, document)
	require.NoError(t, err)

	// QUERY store document on ORG2 (remote)
	err = contractORG2.StorePrivateDocument(txContextORG1, ORG2.Name, document)
	require.NoError(t, err)

	// ### org1 signs document:
	// QUERY create storage key
	storagekeyORG1 := contractORG1.CreateStorageKey(document, ORG1.Name)
	// create signature (later provided by external API/client)
	signatureORG1 := `{signer: "User1@ORG1", pem: "-----BEGIN CERTIFICATE--- ...", signature: "0x123..." }`
	// start tx
	mockStub.MockTransactionStart("tx1")
	// INVOKE storeSignature (here only org1, can also be all endorsers)
	err = contractORG1.StoreSignature(txContextORG1, storagekeyORG1, signatureORG1)
	require.NoError(t, err)
	// execute tx
	mockStub.MockTransactionEnd("tx1")

	// ### org2 signs document:
	// QUERY create storage key
	storagekeyORG2 := contractORG2.CreateStorageKey(document, ORG2.Name)
	// create signature (later provided by external API/client)
	signatureORG2 := `{signer: "User1@ORG2", pem: "-----BEGIN CERTIFICATE--- ...", signature: "0x456..." }`
	// start tx
	mockStub.MockTransactionStart("tx2")
	// INVOKE storeSignature (here only org1, can also be all endorsers)
	err = contractORG2.StoreSignature(txContextORG2, storagekeyORG2, signatureORG2)
	require.NoError(t, err)
	// execute tx
	mockStub.MockTransactionEnd("tx2")

	// ### (optional) org1 checks signatures of org2 on document:
	// QUERY create expected key
	storagekeypartnerORG2 := contractORG1.CreateStorageKey(document, ORG2.Name)
	// QUERY GetSignatures
	signatures, err := contractORG1.GetSignatures(txContextORG1, ORG2.Name, storagekeypartnerORG2)
	require.NoError(t, err)
	printSignatureResponse(signatures)

	// ### (optional) org2 checks signatures of org1 on document:
	// QUERY create expected key
	storagekeypartnerORG1 := contractORG2.CreateStorageKey(document, ORG1.Name)
	// QUERY GetSignatures
	signatures, err = contractORG2.GetSignatures(txContextORG2, ORG1.Name, storagekeypartnerORG1)
	require.NoError(t, err)
	printSignatureResponse(signatures)

	/*
		dumpAllPartialStates(t, transactionContext, "owner~type~key")

			//	ledger.DumpLedger()
	*/
}

/*
func TestPutAndGetState2(t *testing.T) {
	chaincodeStub, _, err := prepareContext("org1MSP")
	require.NoError(t, err)

	log.Infof("xxx %s\n", ORG1.Name)

	// write data
	chaincodeStub.MockTransactionStart("tx1")
	err = chaincodeStub.PutState("test", []byte("test1"))
	require.NoError(t, err)
	chaincodeStub.MockTransactionEnd("tx1")

	chaincodeStub.MockTransactionStart("tx2")
	err = chaincodeStub.PutState("test", []byte("test2"))
	require.NoError(t, err)
	chaincodeStub.MockTransactionEnd("tx2")

	res, err := chaincodeStub.GetState("test")
	require.NoError(t, err)

	fmt.Printf("result <%q>\n", string(res))

	//ledger.DumpLedger()
}

*/
func dumpAllPartialStates(t *testing.T, transactionContext *mocks.TransactionContext, keydef string) {
	chaincodeStub := transactionContext.GetStub()
	keysIter, err := chaincodeStub.GetStateByPartialCompositeKey(keydef, []string{})
	require.NoError(t, err)
	if keysIter == nil {
		log.Infof("no results found")
		return
	}

	log.Infof("================= dumping ledger for partial key [%s.*]", keydef)

	defer keysIter.Close()

	for keysIter.HasNext() {
		resp, iterErr := keysIter.Next()
		require.NoError(t, iterErr)
		require.NotNil(t, resp)
		log.Infof("                  ledger[%s] = %s\n", resp.Key, resp.Value)
	}
	log.Infof("================= done")
}

/*

func dumpAllStates(t *testing.T, stub *shimtest.MockStub) {
	keysIter, err := stub.GetStateByRange("", "")
	require.NoError(t, err)
	if keysIter == nil {
		log.Infof("no results found")
		return
	}

	log.Infof("================= dumping ledger")

	defer keysIter.Close()

	for keysIter.HasNext() {
		resp, iterErr := keysIter.Next()
		require.NoError(t, iterErr)
		require.NotNil(t, resp)
		log.Infof("                  ledger[%s] = %s\n", resp.Key, resp.Value)
	}
	log.Infof("================= done")
}

// based on ideas from https://medium.com/coinmonks/tutorial-on-hyperledger-fabrics-chaincode-testing-44c3f260cb2b
func checkState(t *testing.T, stub *shimtest.MockStub, name string, value string) {
	bytes, err := stub.GetState(name)
	require.NoError(t, err)
	require.NotNil(t, bytes)
	require.EqualValues(t, string(bytes), value)
}
*/
/*
func TestGetAllSignatures(t *testing.T) {
	document := "mydocument"

	contract := RoamingSmartContract{restURI: "http://localhost:3333"}

	chaincodeStub, transactionContext, err := prepareContext("org1MSP")
	require.NoError(t, err)

	key1 := CreateSecretKey(document, "org1MSP")

	// start tx
	chaincodeStub.MockTransactionStart("tx1")
	// store signature
	err = contract.StoreSignature(transactionContext, key1, "{ 'payload' : '1', 'signature' : '0xabcd'}")
	require.NoError(t, err)
	// execute tx
	chaincodeStub.MockTransactionEnd("tx1")

	// start tx
	chaincodeStub.MockTransactionStart("tx2")
	// store signature
	err = contract.StoreSignature(transactionContext, key1, "{ 'payload' : '2', 'signature' : '0xabcd'}")
	require.NoError(t, err)
	// execute tx
	chaincodeStub.MockTransactionEnd("tx2")

	// debug
	dumpAllPartialStates(t, transactionContext, "owner~type~key")

	signatures, err := GetSignatures(transactionContext, "org1MSP", key1)
	//TODO: mock setup returns "not implemented" for GetHistoryForKey
	// https://jira.hyperledger.org/browse/FAB-5507
	require.NoError(t, err)

	for i, val := range signatures {
		log.Infof("signature[%d] = %q\n", i, val)
	}

}
*/
