/*
	Chaincode POC
	- hybrid approach
	- offchain data storage (REST interface)
	- hidden communication on chain (only partners can derive storage location)
	- hlf composite keys for storage

	See offchain_test.go for an example workflow with mocked rest interface.

	A short note on the composite key feature
	 * for documentation see https://github.com/hyperledger/fabric-chaincode-go/blob/master/shim/interfaces.go
	 * example:
	   - let objectType = "owner~type~key~identity"
	   - key = CreateCompositeKey(objectType, []string{ "ORG1", "SIGNATURE", "12345", "user1"})
	   - the resulting key result will be "\x00owner~type~key~identity\x00ORG1\x00SIGNATURE\x0012345\x00user1\x00"


	documentation links:
	- https://github.com/hyperledger/fabric-contract-api-go/blob/master/tutorials/getting-started.md
	- https://github.com/hyperledger/fabric-contract-api-go/blob/master/tutorials/using-advanced-features.md
*/

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
	log "github.com/sirupsen/logrus"
)

const compositeKeyDefinition string = "owner~type~key~txid"

// RESTDocument struct as passed to the rest interface
type RESTDocument struct {
	FromMSP  string `json:"FromMSP"`
	ToMSP    string `json:"ToMSP"`
	SenderID string `json:"SenderID"`
	Data     string `json:"Data"`
	DataHash string `json:"DataHash"`
}

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

	// run chaincode
	err = chaincode.Start()
	if err != nil {
		log.Panicf("failed to start chaincode: %s", err.Error())
	}
}

// RoamingSmartContract creates a new hlf contract api
type RoamingSmartContract struct {
	contractapi.Contract
}

// getRESTConfig returns the stored configuration for the rest endpoint
// NOTE: this function should never be exported as it could reveal the network configuration
func (s *RoamingSmartContract) getRESTConfig(ctx contractapi.TransactionContextInterface) (string, error) {
	// the getter will always use the local collection where this chaincode runs
	implicitCollection := "_implicit_org_" + os.Getenv("CORE_PEER_LOCALMSPID")

	// fetch data from implicit collection
	data, err := ctx.GetStub().GetPrivateData(implicitCollection, "REST_URI")
	if err != nil {
		return "", err
	}
	if data == nil {
		return "", fmt.Errorf("REST configuration not set. Please configure it by calling setRESTConfig()")
	}

	// return result
	return string(data), nil
}

// SetRESTConfig stores the rest endpoint config
func (s *RoamingSmartContract) SetRESTConfig(ctx contractapi.TransactionContextInterface) error {
	// get caller msp
	mspID, err := ctx.GetClientIdentity().GetMSPID()
	if err != nil {
		return err
	}

	// the setter will always set the collection that he owns!
	implicitCollection := "_implicit_org_" + mspID

	// uri is stored in transient map to hide it from other organizations
	transMap, err := ctx.GetStub().GetTransient()
	if err != nil {
		return fmt.Errorf("Error getting transient: " + err.Error())
	}

	// fetch transient data
	uri, ok := transMap["uri"]
	if !ok {
		return fmt.Errorf("uri not found in the transient map")
	}

	// store data in implicit collection
	return ctx.GetStub().PutPrivateData(implicitCollection, "REST_URI", uri)
}

// GetEvaluateTransactions returns functions of RoamingSmartContract to be tagged as evaluate (=query)
// see https://godoc.org/github.com/hyperledger/fabric-contract-api-go/contractapi#SystemContract.GetEvaluateTransactions
// note: this is just a hint for the caller, this is not taken into account during invocation
func (s *RoamingSmartContract) GetEvaluateTransactions() []string {
	return []string{"CreateStorageKey", "CreateStorageKeyFromHash", "GetSignatures", "GetStorageLocation", "StorePrivateDocument"}
}

// CreateStorageKey returns the hidden key used for hidden communication based on a document
func (s *RoamingSmartContract) CreateStorageKey(targetMSPID string, documentBase64 string) (string, error) {
	if len(documentBase64) == 0 {
		return "", fmt.Errorf("invalid input: size of document is zero")
	}
	documentHash := sha256.Sum256([]byte(documentBase64))

	return s.CreateStorageKeyFromHash(targetMSPID, hex.EncodeToString(documentHash[:]))
}

// CreateStorageKeyFromHash returns the hidden key used for hidden communication based on a document hash
func (s *RoamingSmartContract) CreateStorageKeyFromHash(targetMSPID string, documentHash string) (string, error) {
	if len(documentHash) != 64 {
		return "", fmt.Errorf("invalid input: size of document hash is invalid: %d != 32", len(documentHash))
	}
	if len(targetMSPID) == 0 {
		return "", fmt.Errorf("invalid input: targetMSPID is empty")
	}
	hash := sha256.Sum256(append([]byte(targetMSPID), documentHash...))
	return hex.EncodeToString(hash[:]), nil
}

// GetSignatures returns all signatures stored in the ledger for this key
func (s *RoamingSmartContract) GetSignatures(ctx contractapi.TransactionContextInterface, targetMSPID string, key string) (map[string]string, error) {
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

	results := make(map[string]string, 0)

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

		txID := attributes[len(attributes)-1]
		log.Infof("state[%s] txID %s = %s", item.GetKey(), txID, item.GetValue())
		results[txID] = string(item.GetValue())
	}

	return results, nil
}

// GetStorageLocation returns the storage location for
// a given storageType and key by using the composite key feature
func (s *RoamingSmartContract) GetStorageLocation(ctx contractapi.TransactionContextInterface, storageType string, key string) (string, error) {
	// get the calling identity
	invokingMSPID, _, err := getCallingIdenties(ctx)
	if err != nil {
		log.Errorf("failed to fetch calling identity: %s", err.Error())
		return "", err
	}
	// get the txID
	txID := ctx.GetStub().GetTxID()

	// construct the storage location
	storageLocation, err := ctx.GetStub().CreateCompositeKey(compositeKeyDefinition, []string{invokingMSPID, storageType, key, txID})

	if err != nil {
		log.Errorf("failed to create composite key: %s", err.Error())
		return "", err
	}

	log.Infof("got composite key for <%s> = 0x%s", compositeKeyDefinition, hex.EncodeToString([]byte(storageLocation)))

	return storageLocation, nil
}

// storeData stores given data with a given type on the ledger
func (s *RoamingSmartContract) storeData(ctx contractapi.TransactionContextInterface, key string, dataType string, data []byte) error {
	// fetch storage location where we will store the data
	storageLocation, err := s.GetStorageLocation(ctx, dataType, key)
	if err != nil {
		log.Errorf("failed to fetch storageLocation: %s", err.Error())
		return err
	}

	// store data
	log.Infof("will store data of type %s on ledger: state[%s] = 0x%s", dataType, storageLocation, hex.EncodeToString(data))
	err = ctx.GetStub().PutState(storageLocation, data)
	if err != nil {
		log.Errorf("failed to store data: %s", err.Error())
		return err
	}

	// send event notification
	err = ctx.GetStub().SetEvent("STORE:"+dataType, []byte(key))
	if err != nil {
		log.Errorf("failed to set event: %s", err.Error())
		return err
	}

	// no error
	return nil
}

// StoreSignature stores a given signature on the ledger
func (s *RoamingSmartContract) StoreSignature(ctx contractapi.TransactionContextInterface, key string, signatureJSON string) error {

	/*TODO:
	err := ctx.GetClientIdentity().AssertAttributeValue("signDocument", "yes")
	if err != nil {
		log.Error("identity is not allowed to sign")
		return err
	}*/

	return s.storeData(ctx, key, "SIGNATURE", []byte(signatureJSON))
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

// StorePrivateDocument will store contract Data locally
// this can be called on a remote peer or locally
func (s *RoamingSmartContract) StorePrivateDocument(ctx contractapi.TransactionContextInterface, targetMSPID string, payloadBase64 string) (string, error) {
	// get the calling identity
	invokingMSPID, invokingUserID, err := getCallingIdenties(ctx)
	if err != nil {
		log.Errorf("failed to fetch MSPID: %s", err.Error())
		return "", err
	}

	// calc hash over the data
	sha256 := sha256.Sum256([]byte(payloadBase64))
	dataHash := hex.EncodeToString(sha256[:])

	// create rest struct
	var document RESTDocument
	document.FromMSP = invokingMSPID
	document.SenderID = invokingUserID
	document.ToMSP = targetMSPID
	document.Data = payloadBase64
	document.DataHash = dataHash
	documentJSON, err := json.Marshal(document)

	if err != nil {
		log.Errorf("failed to marshal json")
		return "", err
	}

	// fetch the configured rest endpoint
	url, err := s.getRESTConfig(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to fetch REST uri: %s", err.Error())
	}

	log.Infof("will send post request to %s", url)

	response, err := http.Post(url, "application/json", bytes.NewBuffer(documentJSON))

	if err != nil {
		log.Errorf("REST request failed. Error: %s", err.Error())
		return "", err
	}

	log.Infof("got response status %s", response.Status)
	if response.StatusCode != 200 {
		log.Errorf("REST request on %s failed. Status: %s", url, response.Status)
		return "", fmt.Errorf("REST request on %s failed. Status: %s", url, response.Status)
	}

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Errorf("failed to decode body (status = %s, header = %s)", response.Status, response.Header)
		return "", err
	}

	// fetch returned hash of the data
	storedDataHash := string(body)
	log.Infof("got response body, stored data hash %s", storedDataHash)

	// verify that the hash from the post request matches our data
	if dataHash != storedDataHash {
		log.Errorf("hash mismatch %s != %s", dataHash, storedDataHash)
		return "", fmt.Errorf("error, hash mismatch")
	}

	return storedDataHash, nil
}
