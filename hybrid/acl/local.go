package acl

import (
	"os"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
	log "github.com/sirupsen/logrus"
)

// LocalCall checks wether this is a local call or not
func LocalCall(ctx contractapi.TransactionContextInterface) bool {
	// get caller msp
	invokingMSPID, err := ctx.GetClientIdentity().GetMSPID()
	if err != nil {
		log.Errorf("ACL LocalCall: failed to fetch MSPID: %s", err)
		return false
	}

	// verify that this is a local call
	if invokingMSPID == os.Getenv("CORE_PEER_LOCALMSPID") {
		// all fine, grant access
		return true
	}

	// access denied
	log.Errorf("ACL LocalCall: ACCESS VIOLATION by %s. Only local calls are allowed", invokingMSPID)
	return false
}
