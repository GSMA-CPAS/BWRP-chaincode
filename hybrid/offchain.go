/*
	Chaincode POC
	- hybrid approach
	- offchain data storage
	- hidden communication on chain (only partners can derive storage location)
	- hlf composite keys for storage

	See offchain_test.go for an example workflow with mocked rest interface.

	A short note on the composite key feature
	 * for documentation see https://github.com/hyperledger/fabric-chaincode-go/blob/master/shim/interfaces.go
	 * example:
	   - let objectType = "owner~type~key~txid"
	   - key = CreateCompositeKey(objectType, []string{ "ORG1", "SIGNATURE", "12345", "user1"})
	   - the resulting key result will be "\x00owner~type~key~txid\x00ORG1\x00SIGNATURE\x0012345\x00abcdef\x00"


	documentation links:
	- https://github.com/hyperledger/fabric-contract-api-go/blob/master/tutorials/getting-started.md
	- https://github.com/hyperledger/fabric-contract-api-go/blob/master/tutorials/using-advanced-features.md
*/

package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"hybrid/acl"
	"hybrid/util"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
	log "github.com/sirupsen/logrus"
)

const compositeKeyDefinition string = "owner~type~key~txid"
const enableDebug = true

var (
	//ErrorAccessDenied is thrown when the ACL prevents the execution
	ErrorAccessDenied = errors.New("Access Denied")
	//ErrorOffchainDBUnconfigured is thrown when the config is not set yet
	ErrorOffchainDBUnconfigured = errors.New("OffchainDB configuration not set. Please configure it by calling setOffchainDBConfig()")
	//ErrorLocalOverrideOnly is thrown when this is no local call
	ErrorLocalOverrideOnly = errors.New("Access Denied: Invalid targetMSPID, only local overrides are allowed")
	//ErrorHashMismatch is thrown when the hashes do not match
	ErrorHashMismatch = errors.New("Hash mismatch")
	//ErrorTransientMissingURI is thrown when the URI is not in the transient storage
	ErrorTransientMissingURI = errors.New("URI not found in the transient map")
)

func main() {
	if enableDebug {
		// set loglevel
		log.SetLevel(log.DebugLevel)
	}

	// instantiate chaincode
	roamingChaincode := initRoamingSmartContract()
	chaincode, err := contractapi.NewChaincode(roamingChaincode)
	if err != nil {
		log.Panicf("failed to create chaincode: %v", err)
		return
	}

	// run chaincode
	err = chaincode.Start()
	if err != nil {
		log.Panicf("failed to start chaincode: %v", err)
	}
}

// RoamingSmartContract creates a new hlf contract api
type RoamingSmartContract struct {
	contractapi.Contract
}

var contract *RoamingSmartContract

func initRoamingSmartContract() *RoamingSmartContract {
	if contract != nil {
		return contract
	}

	var newContract = RoamingSmartContract{}
	contract = &newContract

	return contract
}

// GetOffchainDBConfig returns the stored configuration for the rest endpoint
// ACL restricted to local queries only
func (s *RoamingSmartContract) GetOffchainDBConfig(ctx contractapi.TransactionContextInterface) (string, error) {
	log.Debugf("%s()", util.FunctionName())

	// ACL restricted to local queries only
	if !acl.LocalCall(ctx) {
		return "", ErrorAccessDenied
	}

	config, err := s.getLocalOffchainDBConfig(ctx)

	return config, err
}

// getOffchainDBConfig returns the stored configuration for the rest endpoint
// this is only allowed to be called locally
// NOTE: (1) DO NOT expose this as it might leak sensitive network configuration use GetOffchainDBConfig for this.
//       (2) always use the LOCALMSPID implicit collection here as we need the configuration of _this_ peer
func (s *RoamingSmartContract) getLocalOffchainDBConfig(ctx contractapi.TransactionContextInterface) (string, error) {
	log.Debugf("%s()", util.FunctionName())

	// the getter will always use the local collection where this chaincode runs
	implicitCollection := "_implicit_org_" + os.Getenv("CORE_PEER_LOCALMSPID")

	// fetch data from implicit collection
	data, err := ctx.GetStub().GetPrivateData(implicitCollection, "OFFCHAINDB_URI")
	if err != nil {
		return "", err
	}
	if data == nil {
		return "", ErrorOffchainDBUnconfigured
	}

	// return result
	return string(data), nil
}

// SetOffchainDBConfig stores the rest endpoint config
// ACL restricted to local queries only
func (s *RoamingSmartContract) SetOffchainDBConfig(ctx contractapi.TransactionContextInterface) error {
	log.Debugf("%s()", util.FunctionName())

	// ACL restricted to local queries only
	if !acl.LocalCall(ctx) {
		return ErrorAccessDenied
	}

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
		return fmt.Errorf("Error getting transient: %v", err)
	}

	// fetch transient data
	uri, ok := transMap["uri"]
	if !ok {
		return ErrorTransientMissingURI
	}

	// store config data in implicit collection
	err = ctx.GetStub().PutPrivateData(implicitCollection, "OFFCHAINDB_URI", uri)
	if err != nil {
		return err
	}

	// do wee need to initialise the db?
	err = util.OffchainDatabasePrepare(string(uri))
	return err
}

// GetEvaluateTransactions returns functions of RoamingSmartContract to be tagged as evaluate (=query)
// see https://godoc.org/github.com/hyperledger/fabric-contract-api-go/contractapi#SystemContract.GetEvaluateTransactions
// note: this is just a hint for the caller, this is not taken into account during invocation
func (s *RoamingSmartContract) GetEvaluateTransactions() []string {
	return []string{"GetOffchainDBConfig", "CreateDocumentID", "CreateStorageKey", "GetSignatures", "IsValidSignature", "GetStorageLocation", "StoreDocumentHash", "StorePrivateDocument", "FetchPrivateDocument", "FetchPrivateDocumentIDs"}
}

// CreateDocumentID creates a DocumentID and verifies that is has not been used yet
func (s *RoamingSmartContract) CreateDocumentID(ctx contractapi.TransactionContextInterface) (string, error) {
	log.Debugf("%s()", util.FunctionName())

	// TODO: verify that the golang crypto lib returns random numbers that are good enough to be used here!
	rand32 := make([]byte, 32)
	_, err := rand.Read(rand32)
	if err != nil {
		log.Errorf("failed to generate documentID: %v", err)
		return "", err
	}

	// encode random numbers to hex string
	documentID := hex.EncodeToString(rand32)

	// get the calling MSP
	invokingMSPID, err := ctx.GetClientIdentity().GetMSPID()
	if err != nil {
		log.Errorf("failed to fetch calling MSPID: %v", err)
		return "", err
	}

	// make sure that there is no such document id for this MSP on the ledger yet:
	storageKey, err := s.CreateStorageKey(invokingMSPID, documentID)
	data, err := ctx.GetStub().GetState(storageKey)
	if err != nil {
		log.Errorf("failed to get ledger state: %v", err)
		return "", err
	}

	if data != nil {
		log.Errorf("data for this documentID already exists.")
		return "", fmt.Errorf("data for this documentID already exists")
	}

	// fine, data does not exist on ledger -> the calulated documentID is ok
	return documentID, nil
}

// CreateStorageKey returns the hidden key used for hidden communication based on a documentID and the targetMSP
func (s *RoamingSmartContract) CreateStorageKey(targetMSPID string, documentID string) (string, error) {
	log.Debugf("%s()", util.FunctionName())

	if len(documentID) != 64 {
		return "", fmt.Errorf("invalid input: size of documentID is invalid: %d != 64", len(documentID))
	}
	if len(targetMSPID) == 0 {
		return "", fmt.Errorf("invalid input: targetMSPID is empty")
	}
	hash := sha256.Sum256([]byte(targetMSPID + documentID))
	return hex.EncodeToString(hash[:]), nil
}

// GetSignatures returns all signatures stored in the ledger for this key
func (s *RoamingSmartContract) GetSignatures(ctx contractapi.TransactionContextInterface, targetMSPID string, key string) (map[string]string, error) {
	log.Debugf("%s()", util.FunctionName())

	// query results for composite key without identity
	iterator, err := ctx.GetStub().GetStateByPartialCompositeKey(compositeKeyDefinition, []string{targetMSPID, "SIGNATURE", key})

	if err != nil {
		log.Errorf("failed to query results for partial composite key: %v", err)
		return nil, err
	}

	results := make(map[string]string, 0)

	if iterator == nil {
		log.Infof("no results found")
		return results, nil
	}

	for iterator.HasNext() {
		item, err := iterator.Next()

		if err != nil {
			log.Errorf("failed to iterate results: %v", err)
			return nil, err
		}

		_, attributes, err := ctx.GetStub().SplitCompositeKey(item.GetKey())

		if err != nil {
			log.Errorf("failed to split composite result: %v", err)
			return nil, err
		}

		txID := attributes[len(attributes)-1]
		log.Infof("state[%s] txID %s = %s", item.GetKey(), txID, item.GetValue())
		results[txID] = string(item.GetValue())
	}

	return results, nil
}

// IsValidSignature take 3 arguments (document string, signature string, certificate chain (root certificate at index 0 and client certificate at last index)
func (s *RoamingSmartContract) IsValidSignature(ctx contractapi.TransactionContextInterface, document string, signature string, certListStr string) (int, error) {
	// Unmarshalling certListStr string to certListJSON Array String
	var certListJSON []interface{}
	err := json.Unmarshal([]byte(certListStr), &certListJSON)
	if err != nil {
		return -1, fmt.Errorf("failed to unmarshal certificates arguments: " + err.Error())
	}

	// find the next PEM formatted block (certificate, private key etc) in the input
	block, _ := pem.Decode([]byte(certListJSON[len(certListJSON)-1].(string)))
	if block == nil {
		return -2, fmt.Errorf("failed to decode user certificate PEM, Invalidating")
	}

	// parses a single certificate from the given ASN.1 DER data
	userCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return -3, fmt.Errorf("failed to parse user certificate: " + err.Error())
	}

	// Looping to extract custom extension
	attrExtPresent := false
	var attrExtension pkix.Extension
	var oidCustomAttribute = asn1.ObjectIdentifier{1, 2, 3, 4, 5, 6, 7, 8, 1}
	for _, ext := range userCert.Extensions {
		if ext.Id.Equal(oidCustomAttribute) {
			attrExtPresent = true
			attrExtension = ext
		}
	}

	// Check if Custom Attribute extension is present, if not invalidate
	if attrExtPresent == false {
		return -4, fmt.Errorf("custom attribute extension not present, invalidating")
	}

	// Unmarshaling custom extension JSON value
	var result map[string]interface{}
	err = json.Unmarshal(attrExtension.Value, &result)
	if err != nil {
		return -5, fmt.Errorf("failed to unmarshal custom attribute json: " + err.Error())
	}

	// check if Custom attribute extension JSON has key "attrs", if not invalidate
	attrValue, exist := result["attrs"].(map[string]interface{})
	if exist {
		if canSignValue, canSignExist := attrValue["CanSignDocument"].(string); canSignExist {
			if strings.EqualFold(canSignValue, "yes") != true {
				return -8, fmt.Errorf("cansigndocument attribute value is not yes, invalidating")
			}
		} else {
			return -7, fmt.Errorf("canSignDocument attribute is not present, invalidating")
		}
	} else {
		return -6, fmt.Errorf("custom attribute json doesn't have attribute attrs, invalidating")
	}

	// Adding root certificate to CertPool for validation
	roots := x509.NewCertPool()
	ok := roots.AppendCertsFromPEM([]byte(certListJSON[0].(string)))
	if !ok {
		return -9, fmt.Errorf("failed to append root certificate to cert pool")
	}

	// If Certificate length is more than 2 then consider intermediate certificate for validation
	// else validate root and user certificates only
	var opts x509.VerifyOptions
	if len(certListJSON) > 2 {
		inters := x509.NewCertPool()
		for i := 1; i < len(certListJSON)-1; i++ {
			ok := inters.AppendCertsFromPEM([]byte(certListJSON[i].(string)))
			if !ok {
				return -10, fmt.Errorf("failed to append intermediate certificate to cert pool")
			}
		}

		// verifying user certificate with root and intermediate certificates
		opts = x509.VerifyOptions{
			Roots:         roots,
			Intermediates: inters,
		}
	} else {
		// verifying user certificate with root certificate only
		opts = x509.VerifyOptions{
			Roots: roots,
		}
	}

	if _, err := userCert.Verify(opts); err != nil {
		return -11, fmt.Errorf("failed to verify user certificate: " + err.Error())
	}

	log.Infof("IsValidSignature: CanSignDocument[%s] PublicKeyAlgorithm[%s] SignatureAlgorithm[%s]", attrValue["CanSignDocument"].(string), userCert.PublicKeyAlgorithm, userCert.SignatureAlgorithm)

	// verifies that signature is a valid signature over signed hashed data document from cert's public key
	if err = userCert.CheckSignature(userCert.SignatureAlgorithm, []byte(document), []byte(signature)); err != nil {
		return -12, fmt.Errorf("signature validation failed: " + err.Error())
	}
	log.Infof("IsValidSignature: Valid")

	// document is valid
	return 0, nil
}

// GetStorageLocation returns the storage location for
// a given storageType and key by using the composite key feature
func (s *RoamingSmartContract) GetStorageLocation(ctx contractapi.TransactionContextInterface, storageType string, key string) (string, error) {
	log.Debugf("%s()", util.FunctionName())

	// get the calling MSP
	invokingMSPID, err := ctx.GetClientIdentity().GetMSPID()
	if err != nil {
		log.Errorf("failed to fetch calling MSPID: %v", err)
		return "", err
	}

	// get the txID
	txID := ctx.GetStub().GetTxID()

	// construct the storage location
	storageLocation, err := ctx.GetStub().CreateCompositeKey(compositeKeyDefinition, []string{invokingMSPID, storageType, key, txID})

	if err != nil {
		log.Errorf("failed to create composite key: %v", err)
		return "", err
	}

	log.Infof("got composite key for <%s> = 0x%s", compositeKeyDefinition, hex.EncodeToString([]byte(storageLocation)))

	return storageLocation, nil
}

// storeData stores given data with a given type on the ledger
func (s *RoamingSmartContract) storeData(ctx contractapi.TransactionContextInterface, key string, dataType string, data []byte) error {
	log.Debugf("%s()", util.FunctionName())

	// get the calling MSP
	invokingMSPID, err := ctx.GetClientIdentity().GetMSPID()
	if err != nil {
		log.Errorf("failed to fetch calling MSPID: %v", err)
		return err
	}

	// fetch storage location where we will store the data
	storageLocation, err := s.GetStorageLocation(ctx, dataType, key)
	if err != nil {
		log.Errorf("failed to fetch storageLocation: %v", err)
		return err
	}

	// store data
	log.Infof("will store data of type %s on ledger: state[%s] = 0x%s", dataType, storageLocation, hex.EncodeToString(data))
	err = ctx.GetStub().PutState(storageLocation, data)
	if err != nil {
		log.Errorf("failed to store data: %v", err)
		return err
	}

	// fetch tx creation time
	txTimestamp, err := ctx.GetStub().GetTxTimestamp()
	if err != nil {
		log.Errorf("failed to fetch tx creation timestamp: %v", err)
		return err
	}

	// build event object
	eventName := "STORE:" + dataType
	timestampString := time.Unix(txTimestamp.Seconds, int64(txTimestamp.Nanos)).Format(time.RFC3339)

	payload := `{ ` +
		`"msp" : "` + invokingMSPID + `", ` +
		`"eventName" : "` + eventName + `", ` +
		`"timestamp" : "` + timestampString + `", ` +
		`"data" : { "storageKey" : "` + key + `" }` +
		` }`

	log.Infof("sending event %s: %s", eventName, payload)
	err = ctx.GetStub().SetEvent(eventName, []byte(payload))
	if err != nil {
		log.Errorf("failed to set event: %v", err)
		return err
	}

	// no error
	return nil
}

// StoreSignature stores a given signature on the ledger
func (s *RoamingSmartContract) StoreSignature(ctx contractapi.TransactionContextInterface, key string, signatureJSON string) error {
	log.Debugf("%s()", util.FunctionName())
	return s.storeData(ctx, key, "SIGNATURE", []byte(signatureJSON))
}

// StoreDocumentHash stores a given document hash on the ledger
func (s *RoamingSmartContract) StoreDocumentHash(ctx contractapi.TransactionContextInterface, key string, documentHash string) error {
	log.Debugf("%s()", util.FunctionName())
	return s.storeData(ctx, key, "DOCUMENTHASH", []byte(documentHash))
}

// StorePrivateDocument will store contract Data locally
// this can be called on a remote peer or locally
// payload is a DataPayload object that contains a nonce and the payload
func (s *RoamingSmartContract) StorePrivateDocument(ctx contractapi.TransactionContextInterface, targetMSPID string, documentID string, documentBase64 string) (string, error) {
	log.Debugf("%s()", util.FunctionName())

	// verify passed data
	if len(documentID) != 64 {
		return "", fmt.Errorf("invalid input: size of documentID is invalid: %d != 64", len(documentID))
	}

	// get the calling MSP
	invokingMSPID, err := ctx.GetClientIdentity().GetMSPID()
	if err != nil {
		log.Errorf("failed to fetch MSPID: %v", err)
		return "", err
	}

	// only allow target override if called locally
	localMSPID := os.Getenv("CORE_PEER_LOCALMSPID")
	if invokingMSPID != localMSPID {
		// called from a external MSP
		if targetMSPID != localMSPID {
			// external MSP wants to set an invalid targetMSP
			return "", ErrorLocalOverrideOnly
		}
	}

	// calc hash over the data
	sha256 := sha256.Sum256([]byte(documentBase64))
	dataHash := hex.EncodeToString(sha256[:])

	// create rest struct
	var document = util.OffchainData{}
	document.TimeStamp = strconv.FormatInt(time.Now().UnixNano(), 10)
	document.Data = documentBase64
	document.DataHash = dataHash
	document.FromMSP = invokingMSPID
	document.ToMSP = targetMSPID

	if err != nil {
		log.Errorf("failed to marshal json")
		return "", err
	}

	// fetch the configured rest endpoint
	uri, err := s.getLocalOffchainDBConfig(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to fetch OffchainDB uri: %v", err)
	}

	// store data in offchain db
	storedDataHash, err := util.OffchainDatabaseStore(uri, documentID, document)
	if err != nil {
		log.Errorf("failed to store data: %v", err)
		return "", err
	}

	log.Infof("stored data ok. saved data hash %s", storedDataHash)

	// verify that the hash from the post request matches our data
	if dataHash != storedDataHash {
		log.Errorf("hash mismatch %s != %s", dataHash, storedDataHash)
		return "", ErrorHashMismatch
	}

	return storedDataHash, nil
}

// FetchPrivateDocument will return a private document identified by its documentID
// ACL restricted to local queries only
func (s *RoamingSmartContract) FetchPrivateDocument(ctx contractapi.TransactionContextInterface, documentID string) (string, error) {
	log.Debugf("%s()", util.FunctionName())

	// ACL restricted to local queries only
	if !acl.LocalCall(ctx) {
		return "", ErrorAccessDenied
	}

	log.Infof("accessing private document with id " + documentID)

	// fetch the configured rest endpoint
	uri, err := s.getLocalOffchainDBConfig(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to fetch OffchainDB uri: %v", err)
	}

	// fetch from database
	data, err := util.OffchainDatabaseFetch(uri, documentID)
	if err != nil {
		log.Errorf("db access failed. Error: %v", err)
		return "", err
	}

	// convert to clean json without couchdb "leftovers"
	dataJSON, err := data.MarshalToCleanJSON()
	if err != nil {
		log.Errorf("failed to convert data from db to json: %v", err)
		return "", err
	}

	// return result
	return string(dataJSON), nil
}

// DeletePrivateDocument will delete a private document identified by its documentID from the database
// ACL restricted to local queries only
func (s *RoamingSmartContract) DeletePrivateDocument(ctx contractapi.TransactionContextInterface, documentID string) error {
	log.Debugf("%s()", util.FunctionName())

	// ACL restricted to local queries only
	if !acl.LocalCall(ctx) {
		return ErrorAccessDenied
	}

	log.Infof("deleting private document with id " + documentID)

	// fetch the configured rest endpoint
	uri, err := s.getLocalOffchainDBConfig(ctx)
	if err != nil {
		return fmt.Errorf("failed to fetch OffchainDB uri: %v", err)
	}

	// fetch from database
	err = util.OffchainDatabaseDelete(uri, documentID)
	if err != nil {
		log.Errorf("db delete access failed. Error: %v", err)
		return err
	}

	// all fine
	return nil
}

// FetchPrivateDocumentIDs will return a list of IDS of the private documents
// ACL restricted to local queries only
func (s *RoamingSmartContract) FetchPrivateDocumentIDs(ctx contractapi.TransactionContextInterface) (string, error) {
	log.Debugf("%s()", util.FunctionName())

	// ACL restricted to local queries only
	if !acl.LocalCall(ctx) {
		return "", ErrorAccessDenied
	}

	// fetch the configured rest endpoint
	uri, err := s.getLocalOffchainDBConfig(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to fetch OffchainDB uri: %v", err)
	}

	// fetch from database
	ids, err := util.OffchainDatabaseFetchAllDocumentIDs(uri)
	if err != nil {
		log.Errorf("db access failed. Error: %v", err)
		return "", err
	}

	// convert array to json
	json, err := json.Marshal(ids)
	if err != nil {
		log.Errorf("failed to convert document IDs to json: %v", err)
		return "", fmt.Errorf("failed to convert document IDs to json: %v", err)
	}

	return string(json), nil
}
