package offchain

//see https://github.com/hyperledger/fabric-samples/blob/master/asset-transfer-basic/chaincode-go/chaincode/smartcontract_test.go

import (
	"chaincode/offchain_rest/mocks"
	"chaincode/offchain_rest/mockstub"
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

const cert = `-----BEGIN CERTIFICATE-----
MIICbjCCAhWgAwIBAgIQDOFK5ymReal7+p2habPWejAKBggqhkjOPQQDAjCBlTEQ
MA4GA1UEBhMHR2VybWFueTEPMA0GA1UECBMGQmVybGluMQ8wDQYDVQQHEwZCZXJs
aW4xFDASBgNVBAkTC0hhdXB0c3RyLiAxMQ4wDAYDVQQREwUxMDExNzEaMBgGA1UE
ChMRYXRlbC5ub2RlbmVjdC5jb20xHTAbBgNVBAMTFGNhLmF0ZWwubm9kZW5lY3Qu
Y29tMB4XDTE5MTAyMTEwMDUwMFoXDTI5MTAxODEwMDUwMFowgY0xEDAOBgNVBAYT
B0dlcm1hbnkxDzANBgNVBAgTBkJlcmxpbjEPMA0GA1UEBxMGQmVybGluMRQwEgYD
VQQJEwtIYXVwdHN0ci4gMTEOMAwGA1UEERMFMTAxMTcxDzANBgNVBAsTBmNsaWVu
dDEgMB4GA1UEAwwXQWRtaW5AYXRlbC5ub2RlbmVjdC5jb20wWTATBgcqhkjOPQIB
BggqhkjOPQMBBwNCAAQVvt/VE+1L+sIYQH0HklhrP/FXuryomsVGvWNMnvJUtqu+
8r5t8si56qApO41g2+WIJZrjUBYgdrSB2yRgQ2/8o00wSzAOBgNVHQ8BAf8EBAMC
B4AwDAYDVR0TAQH/BAIwADArBgNVHSMEJDAigCC1O2t3N76Q4z2wSagPevCdTjbv
RdCmMZops5IRJ8W4pTAKBggqhkjOPQQDAgNHADBEAiBx74S2GTEscgAKwmWL5RpD
y1cOxZNf4ydNmkTbfbB3yAIgPAoBX/zPDtWHRwrcXqnhGe/gRY0gH4kiiem3YFZE
6fM=
-----END CERTIFICATE-----
`

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

/*
func TestGetAllSignatures(t *testing.T) {
	document := "mydocument"

	contract := RoamingSmartContract{}
	shimStub := shimtest.NewMockStub("Test", nil)

	shimStub.Creator, _ = fakeCreator(t, "org1MSP", []byte(cert))

	clientID, err := cid.New(shimStub)
	require.NoError(t, err)
	transactionContext := &mocks.TransactionContext{}

	transactionContext.GetStubReturns(shimStub)
	transactionContext.GetClientIdentityReturns(clientID)

	key1 := CreateSecretKey(document, "org1MSP")

	// start tx
	shimStub.MockTransactionStart("txid_dummy_init1")
	// store signature
	err = contract.StoreSignature(transactionContext, key1, "{ 'payload' : '1', 'signature' : '0xabcd'}")
	require.NoError(t, err)
	// execute tx
	shimStub.MockTransactionEnd("txid_dummy_init1")

	// start tx
	shimStub.MockTransactionStart("txid_dummy_init2")
	// store signature
	err = contract.StoreSignature(transactionContext, key1, "{ 'payload' : '2', 'signature' : '0xabcd'}")
	require.NoError(t, err)
	// execute tx
	shimStub.MockTransactionEnd("txid_dummy_init2")

	// debug
	dumpAllPartialStates(t, shimStub, "owner~type~key")

	signatures, err := GetSignatures(transactionContext, "org1MSP", key1)
	//TODO: mock setup returns "not implemented" for GetHistoryForKey
	// https://jira.hyperledger.org/browse/FAB-5507
	require.NoError(t, err)

	for i, val := range signatures {
		log.Infof("signature[%d] = %q\n", i, val)
	}

}
*/

func prepareStubs() (*mocks.TransactionContext, error) {
	chaincodeStub := &mocks.ChaincodeStub{}
	ledger := mockstub.NewLedger(chaincodeStub)

	creator, err := fakeCreator("org1MSP", []byte(cert))
	chaincodeStub.GetCreatorReturns(creator, err)

	clientID, err := cid.New(chaincodeStub)
	if err != nil {
		return nil, err
	}

	// tell the mock setup what to return
	transactionContext := &mocks.TransactionContext{}
	transactionContext.GetStubReturns(chaincodeStub)
	transactionContext.GetClientIdentityReturns(clientID)

	// tell the mock which functions to use
	chaincodeStub.CreateCompositeKeyCalls(shim.CreateCompositeKey)
	chaincodeStub.PutStateCalls(ledger.PutState)
	chaincodeStub.GetStateCalls(ledger.GetState)
	chaincodeStub.GetStateByPartialCompositeKeyReturns(ledger.GetStateByPartialCompositeKey, nil)

	return transactionContext, nil
}

func TestStoreSignature(t *testing.T) {
	contract := RoamingSmartContract{}

	transactionContext, err := prepareStubs()
	require.NoError(t, err)

	// start tx
	//shimStub.MockTransactionStart("txid_dummy_init")

	// test storesignature
	key := "0x01234KEY"
	err = contract.StoreSignature(transactionContext, key, "\x1234")
	require.NoError(t, err)

	// execute tx
	//shimStub.MockTransactionEnd("txid_dummy_init")

	dumpAllPartialStates(t, transactionContext, "owner~type~key")

	//	ledger.DumpLedger()
}

func TestPutAndGetState2(t *testing.T) {
	transactionContext, err := prepareStubs()
	require.NoError(t, err)

	// write data
	chaincodeStub := transactionContext.GetStub()
	chaincodeStub.PutState("test", []byte("test1"))
	chaincodeStub.PutState("test", []byte("test2"))

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
