/*
 */

package offchain

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
	log "github.com/sirupsen/logrus"
)

const compositeKeyDefinition string = "owner~type~key~identity"

func main() {
	// set loglevel
	log.SetLevel(log.DebugLevel)

	// instantiate chaincode
	roamingChaincode := new(RoamingSmartContract)
	chaincode, err := contractapi.NewChaincode(roamingChaincode)
	if err != nil {
		log.Panicf("failed to create chaincode: %s", err.Error())
		return
	}

	// configure chaincode
	restURI := os.Getenv("ROAMING_CHAINCODE_REST_URI")
	if restURI == "" {
		// default for uninitialized env vars
		restURI = "http://localhost:3333"
	}
	roamingChaincode.restURI = restURI

	// run chaincode
	err = chaincode.Start()
	if err != nil {
		log.Panicf("failed to start chaincode: %s", err.Error())
	}
}

// RoamingSmartContract creates a new hlf contract api
type RoamingSmartContract struct {
	contractapi.Contract
	restURI string
}

// CreateStorageKey returns the hidden key used for hidden communication
func (s *RoamingSmartContract) CreateStorageKey(document []byte, targetMSPID string) string {
	hash := sha256.Sum256(append([]byte(targetMSPID), document...))
	return hex.EncodeToString(hash[:])
}

// GetSignatures returns all signatures stored in the ledger for this key
func (s *RoamingSmartContract) GetSignatures(ctx contractapi.TransactionContextInterface, targetMSPID string, key string) (map[string][]byte, error) {
	// query results for composite key without identity
	iterator, err := ctx.GetStub().GetStateByPartialCompositeKey(compositeKeyDefinition, []string{targetMSPID, "SIGNATURE", key})

	if err != nil {
		log.Errorf("failed to query results for partial composite key: %s", err.Error())
		return nil, err
	}

	if iterator == nil {
		log.Infof("no results found")
		return nil, fmt.Errorf("GetSignatures found no results")
	}

	results := make(map[string][]byte, 0)

	for iterator.HasNext() {
		item, err := iterator.Next()

		if err != nil {
			log.Errorf("failed to iterate results: %s", err.Error())
			return nil, err
		}

		_, attributes, err := ctx.GetStub().SplitCompositeKey(item.GetKey())

		if err != nil {
			log.Errorf("failed to split composite result: %s", err.Error())
			return nil, err
		}

		log.Infof("state[%s] = %s", item.GetKey(), item.GetValue())
		results[attributes[len(attributes)-1]] = item.GetValue()
	}

	return results, nil
}

// GetStorageLocation returns the storage location for
// a given storageType and key by using the composite key feature
func GetStorageLocation(ctx contractapi.TransactionContextInterface, storageType string, key string) (string, error) {
	// get the calling identity
	invokingMSPID, invokingUserID, err := getCallingIdenties(ctx)
	if err != nil {
		log.Errorf("failed to fetch calling identity: %s", err.Error())
		return "", err
	}

	// construct the storage location
	storageLocation, err := ctx.GetStub().CreateCompositeKey(compositeKeyDefinition, []string{invokingMSPID, storageType, key, invokingUserID})

	if err != nil {
		log.Errorf("failed to create composite key: %s", err.Error())
		return "", err
	}

	log.Infof("got composite key for <%s> = 0x%s", compositeKeyDefinition, hex.EncodeToString([]byte(storageLocation)))

	return storageLocation, nil
}

// StoreData stores given data with a given type on the ledger
func StoreData(ctx contractapi.TransactionContextInterface, key string, dataType string, data []byte) error {
	// fetch storage location where we will store the data
	storageLocation, err := GetStorageLocation(ctx, dataType, key)
	if err != nil {
		log.Errorf("failed to fetch storageLocation: %s", err.Error())
		return err
	}

	// TODO: IDEA/CHECK with martin:
	// instead of manually appending data (i.e. ledger[key] = ledger[key] . {newdata} )
	// we could just overwrite data and use getHistoryForKey(key) to retrieve all values?
	// NOTE: this method requires peer configuration core.ledger.history.enableHistoryDatabase to be true!
	log.Infof("will store data of type %s on ledger: state[%s] = 0x%s", dataType, storageLocation, hex.EncodeToString(data))
	return ctx.GetStub().PutState(storageLocation, data)
}

// StoreSignature stores a given signature on the ledger
func (s *RoamingSmartContract) StoreSignature(ctx contractapi.TransactionContextInterface, key string, signatureJSON string) error {
	return StoreData(ctx, key, "SIGNATURE", []byte(signatureJSON))
}

// getCallingIdenties returns the caller MSPID and userID
func getCallingIdenties(ctx contractapi.TransactionContextInterface) (string, string, error) {
	// fetch calling MSP ID
	mspID, err := ctx.GetClientIdentity().GetMSPID()
	if err != nil {
		log.Errorf("failed to get calling identity: %s", err.Error())
		return "", "", err
	}

	userID, err := ctx.GetClientIdentity().GetID()
	if err != nil {
		log.Errorf("failed to get calling user ID: %s", err.Error())
		return "", "", err
	}

	log.Infof("got IDs for MSP=%s and user=%s", mspID, userID)
	return mspID, userID, nil
}

/*
CreateSignature(document):
TODO: to in API
-	Query function
-	Creates signature over data using globally defined signature algorithm with caller’s HLF key
-	Returns signature, signature_algorithm
crypto/ed25519 - Golang
{algorithm: ed25519
identity: User1@org1
publicCert: X509Certificate
signature: signature}
*/

// StorePrivateDocument will store contract Data locally
// this can be called on a remote peer or locally
func (s *RoamingSmartContract) StorePrivateDocument(ctx contractapi.TransactionContextInterface, targetMSPID string, document []byte) error {
	// get the calling identity
	invokingMSPID, invokingUserID, err := getCallingIdenties(ctx)
	if err != nil {
		log.Errorf("failed to fetch MSPID: %s", err.Error())
		return err
	}

	// send data via a REST request to the DB
	// todo: use a special hostname (e.g. rest_service.local) instead of localhost
	url := s.restURI + "/write/" + url.QueryEscape(invokingMSPID) + "/" + url.QueryEscape(targetMSPID) + "/" + url.QueryEscape(invokingUserID)
	log.Infof("will send post request to %s", url)

	response, err := http.Post(url, "application/json", bytes.NewBuffer(document))

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
