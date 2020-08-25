package offchain

//see https://github.com/hyperledger/fabric-samples/blob/master/asset-transfer-basic/chaincode-go/chaincode/smartcontract_test.go

import (
	"chaincode/offchain_rest/historyshimtest"
	"chaincode/offchain_rest/mocks"
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

func prepareTransactionContext(stub *historyshimtest.MockStub, orgmsp string, cert []byte) (*mocks.TransactionContext, error) {
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

func TestStoreSignature(t *testing.T) {
	// a binary test document:
	document := []byte(`data!1234...`)
	// create signature (later provided by external API/client)
	//signatureORG1 := `{signer: "User1@ORG1", pem: "-----BEGIN CERTIFICATE--- ...", signature: "0x123..." }`
	//signatureORG2 := `{signer: "User2@ORG1", pem: "-----BEGIN CERTIFICATE--- ...", signature: "0x456..." }`

	// create internal state map
	mockStub := historyshimtest.NewMockStub("roamingState", nil)

	// init contracts
	contractORG1 := RoamingSmartContract{restURI: "http://localhost:3001"}
	contractORG2 := RoamingSmartContract{restURI: "http://localhost:3002"}

	txContextORG1, err := prepareTransactionContext(mockStub, ORG1.Name, ORG1.Certificate)
	require.NoError(t, err)
	//txContextORG2,err := prepareTransactionContext(mockStub, ORG2.Name, ORG2.Certificate)
	//require.NoError(t, err)

	// store document on ORG1 (local)
	err = contractORG1.StorePrivateDocument(txContextORG1, ORG2.Name, document)
	require.NoError(t, err)

	// store document on ORG2 (remote)
	err = contractORG2.StorePrivateDocument(txContextORG1, ORG2.Name, document)
	require.NoError(t, err)

	// org1 signs document:

	/*
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
