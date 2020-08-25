package offchain

//see https://github.com/hyperledger/fabric-samples/blob/master/asset-transfer-basic/chaincode-go/chaincode/smartcontract_test.go

import (
	"chaincode/offchain_rest/historyshimtest"
	"chaincode/offchain_rest/mocks"
	"fmt"
	"testing"

	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric-chaincode-go/pkg/cid"
	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-contract-api-go/contractapi"
	"github.com/hyperledger/fabric-protos-go/msp"
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

func fakeCreator(mspID string, idbytes []byte) ([]byte, error) {
	sid := &msp.SerializedIdentity{Mspid: mspID, IdBytes: idbytes}
	b, err := proto.Marshal(sid)
	return b, err
}

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

func prepareContext(stub *historyshimtest.MockStub, orgmsp string, cert []byte) (*mocks.TransactionContext, error) {
	creator, err := fakeCreator(orgmsp, cert)
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

func queryStorePrivateDocument(transactionContext *TransactionContext, document []byte, orgReceiver string, targetPeer string) error {
	//init chaincode
	contract := RoamingSmartContract{}

	//StorePrivateDocument
	err = contract.StorePrivateDocument(transactionContext, orgReceiver, document)
	return err
}

func TestStoreSignature(t *testing.T) {
	const org1Name = `org1`
	const org2Name = `org2`

	//a binary test document:
	document := []byte(`data!1234...`)
	//create signature (later provided by external API/client)
	signature := `{signer: "User1", pem: "-----BEGIN CERTIFICATE--- ...", signature: "0x123" }`

	//create internal state map
	mockStub := historyshimtest.NewMockStub("roamingState", nil)

	contextOrg1, err := prepareContext(mockStub, org1Name, []byte(certOrg1))
	//contextOrg2,err := prepareContext(mockStub, org2Name, []byte(certOrg2))

	//send document locally on org1
	queryStorePrivateDocument(contextOrg1, document, org1Name, `peer0.org1`)

	//send document from org1 to org2
	queryStorePrivateDocument(contextOrg1, document, org1Name, `peer0.org2`)

	//init chaincode
	contract := RoamingSmartContract{}
	chaincodeStub, transactionContext, err := prepareContext("org1MSP")
	require.NoError(t, err)

	//store secret document on both orgs

	// start tx
	chaincodeStub.MockTransactionStart("tx1")

	// test storesignature
	key := "0x01234KEY"
	err = contract.StoreSignature(transactionContext, key, "\x1234")
	require.NoError(t, err)

	// execute tx
	chaincodeStub.MockTransactionEnd("tx1")

	dumpAllPartialStates(t, transactionContext, "owner~type~key")

	//	ledger.DumpLedger()
}

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
