package main

//see https://github.com/hyperledger/fabric-samples/blob/master/asset-transfer-basic/chaincode-go/chaincode/smartcontract_test.go

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hybrid/historyshimtest"
	"hybrid/mocks"
	"io/ioutil"
	"net/http"
	"os"
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
	body, _ := ioutil.ReadAll(c.Request().Body)
	log.Infof("on %s got: %s", c.Echo().Server.Addr, string(body))

	var document map[string]interface{}
	json.Unmarshal(body, &document)

	data := document["Data"].(string)
	hash := sha256.Sum256([]byte(data))

	// return the hash in the same way as the offchain-db-adapter
	return c.String(http.StatusOK, hex.EncodeToString(hash[:]))
}

func startRestServer(port int) {
	e := echo.New()

	// define routes
	e.POST("/documents", showRestData)

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

	// init contracts
	contractORG1 := RoamingSmartContract{}
	contractORG2 := RoamingSmartContract{}

	// create internal state map
	mockStub := historyshimtest.NewMockStub("roamingState", nil)

	// ### Org1 creates a document and sends it to Org2:
	// a test document:
	documentBase64 := base64.StdEncoding.EncodeToString([]byte(`data!1234...`))

	// Prepare transient data map
	var transient map[string][]byte
	transient = make(map[string][]byte)

	// ORG1 as "sender"
	txContextORG1, err := prepareTransactionContext(mockStub, ORG1.Name, ORG1.Certificate)
	require.NoError(t, err)

	// ORG2 as "receiver" and later signer
	txContextORG2, err := prepareTransactionContext(mockStub, ORG2.Name, ORG2.Certificate)
	require.NoError(t, err)

	// Set transient data for Org1
	transient["uri"] = []byte("http://localhost:3001/documents")
	mockStub.TransientMap = transient
	err = contractORG1.SetRESTConfig(txContextORG1)
	require.NoError(t, err)

	// read back for debugging
	// note that this is not allowed on chaincode calls
	// as getRESTConfig is not exported
	os.Setenv("CORE_PEER_LOCALMSPID", ORG1.Name)
	uri, err := contractORG1.getRESTConfig(txContextORG1)
	fmt.Printf("> read back uri <%s>\n", uri)
	require.NoError(t, err)

	// Set transient data for Org2
	transient["uri"] = []byte("http://localhost:3002/documents")
	mockStub.TransientMap = transient
	err = contractORG2.SetRESTConfig(txContextORG2)
	require.NoError(t, err)

	// QUERY store document on ORG1 (local)
	_, err = contractORG1.StorePrivateDocument(txContextORG1, ORG2.Name, documentBase64)
	require.NoError(t, err)

	// QUERY store document on ORG2 (remote)
	_, err = contractORG2.StorePrivateDocument(txContextORG1, ORG2.Name, documentBase64)
	require.NoError(t, err)

	// ### org1 signs document:
	// QUERY create storage key
	storagekeyORG1, err := contractORG1.CreateStorageKey(documentBase64, ORG1.Name)
	require.NoError(t, err)
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
	storagekeyORG2, err := contractORG2.CreateStorageKey(documentBase64, ORG2.Name)
	require.NoError(t, err)
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
	storagekeypartnerORG2, err := contractORG1.CreateStorageKey(documentBase64, ORG2.Name)
	require.NoError(t, err)
	// QUERY GetSignatures
	signatures, err := contractORG1.GetSignatures(txContextORG1, ORG2.Name, storagekeypartnerORG2)
	require.NoError(t, err)
	printSignatureResponse(signatures)

	// ### (optional) org2 checks signatures of org1 on document:
	// QUERY create expected key
	storagekeypartnerORG1, err := contractORG2.CreateStorageKey(documentBase64, ORG1.Name)
	require.NoError(t, err)
	// QUERY GetSignatures
	signatures, err = contractORG2.GetSignatures(txContextORG2, ORG1.Name, storagekeypartnerORG1)
	require.NoError(t, err)
	printSignatureResponse(signatures)

}
