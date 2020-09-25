package chaincode

import (
	"hybrid/test/historyshimtest"
	"hybrid/test/mocks"

	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric-chaincode-go/pkg/cid"
	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-contract-api-go/contractapi"
	"github.com/hyperledger/fabric-protos-go/msp"
	log "github.com/sirupsen/logrus"
)

//go:generate counterfeiter -o test/mocks/chaincodestub.go -fake-name ChaincodeStub . chaincodeStub
type chaincodeStub interface {
	shim.ChaincodeStubInterface
}

//go:generate counterfeiter -o test/mocks/transaction.go -fake-name TransactionContext . transactionContext
type transactionContext interface {
	contractapi.TransactionContextInterface
}

func createIdentity(mspID string, idbytes []byte) ([]byte, error) {
	sid := &msp.SerializedIdentity{Mspid: mspID, IdBytes: idbytes}
	b, err := proto.Marshal(sid)
	return b, err
}

func PrepareTransactionContext(stub *historyshimtest.MockStub, orgmsp string, cert []byte) (*mocks.TransactionContext, error) {
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

func PrintSignatureResponse(input map[string]string) {
	for txID, signature := range input {
		log.Infof("txID: %s => signature: %s", txID, signature)
	}
}
