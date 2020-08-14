/*
 */

package offchain

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"

	"github.com/hyperledger/fabric-chaincode-go/pkg/cid"
	"github.com/hyperledger/fabric-contract-api-go/contractapi"
	log "github.com/sirupsen/logrus"
)

func main() {
	// set loglevel
	log.SetLevel(log.DebugLevel)

	// instantiate chaincode
	chaincode, err := contractapi.NewChaincode(new(SmartContract))
	if err != nil {
		log.Panicf("failed to create chaincode: %s", err.Error())
		return
	}

	// run chaincode
	err = chaincode.Start()
	if err != nil {
		log.Panicf("failed to start chaincode: %s", err.Error())
	}
}

// SmartContract creates a new hlf contract api
type SmartContract struct {
	contractapi.Contract
}

// StorePayload will store the given payload in the local db via a ReST call
func StorePayload(partnerMSP string, data string) error {
	// send data via a REST request to the DB
	// todo: use a special hostname (e.g. rest_service.local) instead of localhost
	url := "http://localhost:3333/write/" + partnerMSP + "/0"
	log.Infof("will send post request to %s", url)

	response, err := http.Post(url, "application/json", strings.NewReader(data))

	if err != nil {
		log.Errorf("rest request failed. error: %s", err.Error())
		return err
	}

	log.Infof("got response %s", response.Status)

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Errorf("failed to decode body (status = %s, header = %s)", response.Status, response.Header)
		return err
	}

	log.Infof("got response body %s", string(body))

	return nil
}

// GetCallerMSP returns the caller MSPID
func GetCallerMSPID(ctx contractapi.TransactionContextInterface) (string, error) {

	// fetch cid
	cid, err := cid.New(ctx.GetStub())
	if err != nil {
		log.Errorf("failed to fetch cid: %s", err.Error())
		return "", err
	}

	// fetch callers MSP name
	msp, err := cid.GetMSPID()
	if err != nil {
		log.Errorf("failed to get caller MSPID: %s", err.Error())
		return "", err
	}

	log.Infof("got caller MSPID '%s'", msp)
	return msp, nil
}

// StorePrivateData will store contract Data locally
// this can be called on a remote peer or locally.
// it will store the private data on the called peer
func (s *SmartContract) StorePrivateData(ctx contractapi.TransactionContextInterface, partnerMSPID string, data string) error {
	// fetch local MSPID
	localMSPID := os.Getenv("CORE_PEER_LOCALMSPID")

	// get the caller MSPID
	callerMSPID, err := GetCallerMSPID(ctx)
	if err != nil {
		log.Errorf("failed to fetch MSPID: %s", err.Error())
		return err
	}

	log.Infof(">> got MSPs, local = %s, caller = %s, partner = %s", localMSPID, callerMSPID, partnerMSPID)

	// make sure this is called on the proper peers
	if localMSPID == partnerMSPID {
		log.Info("store private data: remote call")
		return StorePayload(callerMSPID, data)
	} else if localMSPID == callerMSPID {
		log.Info("store private data: local call")
		return StorePayload(partnerMSPID, data)
	}

	log.Errorf("invalid call, partnerMSPID does neither match local nor caller MSPID")
	return fmt.Errorf("invalid call for given partnerMSPID")
}

// safe to store the data:

/*payload_hash :=ctx.GetStub().getState(txID)

	//TODO: fetch/verify mspid

	if (sha256(json_payload) == payload_hash) {
		http.post(localhost:3030/mspid/txID, "json", json_payload)
	}
}
*/
//create instances of chaincode on remote peer, local peer and the endorsing peers
//remote_chaincode = Chaincode(target_org_msp)
//local_chaincode = Chaincode(local_msp)
//endorsing_chaincode = Chaincode(endorsing_channel)

//store the data locally
//do this before pushing to ledger or remote to keep track
//TODO: above comment is bs as we can not storeprivatedata before it is on ledger
//local_chaincode.query(storePrivateData(txID, json_payload))
//TODO: so alternative might be calling this directly or change order by doing the line above after putting on blockchain:
/*	err := StorePayload("mspID", data)
	if err != nil {
		log.Errorf("failed to store payload: %s", err.Error())
		return err
	}
*/
//create chain entry based on the payload
//payload_hash = sha256(json_payload)
//txID = endorsing_chaincode.invoke(putPrivateDataHashOnChain(payload_hash)) //TODO: StatusResponse can contain txid?

//TODO: check data written on remote

//send the data to the remote peer
//remote_chaincode.query(storePrivateData(txID, json_payload))
