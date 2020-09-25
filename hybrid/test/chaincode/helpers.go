package chaincode

import (
	"hybrid/test/historyshimtest"
	"hybrid/test/mocks"

	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-chaincode-go/pkg/cid"
)

// PrepareTransactionContext prepares a tx context
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

// PrintSignatureResponse prints a formatted response
func PrintSignatureResponse(input map[string]string) {
	for txID, signature := range input {
		log.Infof("txID: %s => signature: %s", txID, signature)
	}
}
