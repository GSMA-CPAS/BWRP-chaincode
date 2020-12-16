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
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hybrid/acl"
	"hybrid/certificate"
	"hybrid/errorcode"
	"hybrid/util"
	"os"
	"strconv"
	"time"

	"github.com/golang/protobuf/ptypes"
	"github.com/hyperledger/fabric-contract-api-go/contractapi"
	log "github.com/sirupsen/logrus"
)

const compositeKeyDefinition string = "owner~type~key~txid"
const enableDebug = true

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
		return "", errorcode.NonLocalAccessDenied.LogReturn()
	}
	config, err := s.getLocalOffchainDBConfig(ctx)

	// it is safe to forward local errors
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
		return "", fmt.Errorf("failed to get offchaindb, %v", err)
	}
	if data == nil {
		return "", fmt.Errorf("no data in offchaindb config")
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
		return errorcode.NonLocalAccessDenied.LogReturn()
	}

	// get caller msp
	invokingMSPID, err := ctx.GetClientIdentity().GetMSPID()
	if err != nil {
		return errorcode.Internal.WithMessage("failed to get invoking MSP, %v", err).LogReturn()
	}

	// the setter will always set the collection that he owns!
	implicitCollection := "_implicit_org_" + invokingMSPID

	// uri is stored in transient map to hide it from other organizations
	transMap, err := ctx.GetStub().GetTransient()
	if err != nil {
		return errorcode.Internal.WithMessage("failed to get transient, %v", err).LogReturn()
	}

	// fetch transient data
	uri, ok := transMap["uri"]
	if !ok {
		return errorcode.Internal.WithMessage("transient data is missing").LogReturn()
	}

	// store config data in implicit collection
	err = ctx.GetStub().PutPrivateData(implicitCollection, "OFFCHAINDB_URI", uri)
	if err != nil {
		return errorcode.Internal.WithMessage("failed to store private data, %v", err).LogReturn()
	}

	// do wee need to initialise the db?
	err = util.OffchainDatabasePrepare(string(uri))
	if err != nil {
		return errorcode.Internal.WithMessage("failed to init offchaindb, %v", err).LogReturn()
	}

	// all fine
	return nil
}

// SetCertificate stores the organization certificates on the ledger
// ACL restricted to local queries only
func (s *RoamingSmartContract) SetCertificate(ctx contractapi.TransactionContextInterface, certType string, certData string) error {
	log.Debugf("%s(%s, ...)", util.FunctionName(), certType)

	// get caller msp
	invokingMSPID, err := ctx.GetClientIdentity().GetMSPID()
	if err != nil {
		return errorcode.Internal.WithMessage("failed to get invoking MSP, %v", err).LogReturn()
	}

	// cert storage location:
	storageLocation, err := ctx.GetStub().CreateCompositeKey("msp~configtype~data", []string{invokingMSPID, "certificates", certType})
	if err != nil {
		return errorcode.Internal.WithMessage("failed to get create composite key, %v", err).LogReturn()
	}

	// store given certs
	err = ctx.GetStub().PutState(storageLocation, []byte(certData))
	if err != nil {
		return errorcode.Internal.WithMessage("failed to store certificate  data, %v", err).LogReturn()
	}

	// all fine
	return nil
}

// GetCertificate retrieves the certificate for a given organization from the ledger
func (s *RoamingSmartContract) GetCertificate(ctx contractapi.TransactionContextInterface, msp string, certType string) (string, error) {
	log.Debugf("%s(%s, %s)", util.FunctionName(), msp, certType)

	// cert storage location:
	storageLocation, err := ctx.GetStub().CreateCompositeKey("msp~configtype~data", []string{msp, "certificates", certType})
	if err != nil {
		return "", errorcode.Internal.WithMessage("failed to create composite key, %v", err).LogReturn()
	}

	// store given certs
	certData, err := ctx.GetStub().GetState(storageLocation)
	if err != nil {
		return "", errorcode.Internal.WithMessage("failed to get certificate  data, %v", err).LogReturn()
	}

	// all fine
	return string(certData), nil
}

// GetEvaluateTransactions returns functions of RoamingSmartContract to be tagged as evaluate (=query)
// see https://godoc.org/github.com/hyperledger/fabric-contract-api-go/contractapi#SystemContract.GetEvaluateTransactions
// note: this is just a hint for the caller, this is not taken into account during invocation
func (s *RoamingSmartContract) GetEvaluateTransactions() []string {
	return []string{"GetOffchainDBConfig", "GetCertificate", "CreateDocumentID", "CreateStorageKey", "GetSignatures", "VerifySignatures", "IsValidSignature", "GetStorageLocation", "StoreDocumentHash", "StorePrivateDocument", "FetchPrivateDocument", "FetchPrivateDocumentIDs"}
}

// CreateDocumentID creates a DocumentID and verifies that is has not been used yet
func (s *RoamingSmartContract) CreateDocumentID(ctx contractapi.TransactionContextInterface) (string, error) {
	log.Debugf("%s()", util.FunctionName())

	// TODO: verify that the golang crypto lib returns random numbers that are good enough to be used here!
	rand32 := make([]byte, 32)
	_, err := rand.Read(rand32)
	if err != nil {
		return "", errorcode.Internal.WithMessage("failed to generate documentID, %v", err).LogReturn()
	}

	// encode random numbers to hex string
	documentID := hex.EncodeToString(rand32)

	// get caller msp
	invokingMSPID, err := ctx.GetClientIdentity().GetMSPID()
	if err != nil {
		return "", errorcode.Internal.WithMessage("failed to get invoking MSP, %v", err).LogReturn()
	}

	// make sure that there is no such document id for this MSP on the ledger yet:
	storageKey, err := s.CreateStorageKey(invokingMSPID, documentID)
	if err != nil {
		// it is safe to return local errors
		return "", err
	}

	data, err := ctx.GetStub().GetState(storageKey)
	if err != nil {
		return "", errorcode.Internal.WithMessage("unable to get ledger state, %v", err).LogReturn()
	}

	if data != nil {
		return "", errorcode.DocumentIDExists.WithMessage("data for this documentID %s already exists", documentID).LogReturn()
	}

	// fine, data does not exist on ledger -> the calulated documentID is ok
	return documentID, nil
}

// CreateStorageKey returns the hidden key used for hidden communication based on a documentID and the targetMSP
func (s *RoamingSmartContract) CreateStorageKey(targetMSPID string, documentID string) (string, error) {
	log.Debugf("%s(%s, %s)", util.FunctionName(), targetMSPID, documentID)

	if len(documentID) != 64 {
		return "", errorcode.DocumentIDInvalid.WithMessage("invalid input size of documentID is invalid as %d != 64", len(documentID)).LogReturn()
	}

	if len(targetMSPID) == 0 {
		return "", errorcode.TargetMSPInvalid.WithMessage("invalid input, targetMSPID is empty").LogReturn()
	}
	hash := sha256.Sum256([]byte(targetMSPID + documentID))
	return hex.EncodeToString(hash[:]), nil
}

// GetSignatures returns all signatures stored in the ledger for this documentID
func (s *RoamingSmartContract) GetSignatures(ctx contractapi.TransactionContextInterface, targetMSPID string, documentID string) (map[string]string, error) {
	log.Debugf("%s()", util.FunctionName())

	// calc storage key
	key, err := s.CreateStorageKey(targetMSPID, documentID)
	if err != nil {
		// forwarding local errors is safe
		return nil, err
	}

	// query results for composite key without identity
	iterator, err := ctx.GetStub().GetStateByPartialCompositeKey(compositeKeyDefinition, []string{targetMSPID, "SIGNATURE", key})

	if err != nil {
		return nil, errorcode.Internal.WithMessage("failed to query results for partial composite key, %v", err).LogReturn()
	}

	results := make(map[string]string)

	if iterator == nil {
		log.Infof("no results found")
		return results, nil
	}

	for iterator.HasNext() {
		item, err := iterator.Next()

		if err != nil {
			return nil, errorcode.Internal.WithMessage("failed to iterate results, %v", err).LogReturn()
		}

		_, attributes, err := ctx.GetStub().SplitCompositeKey(item.GetKey())

		if err != nil {
			return nil, errorcode.Internal.WithMessage("failed to split composite result, %v", err).LogReturn()
		}

		txID := attributes[len(attributes)-1]
		log.Infof("state[%s] txID %s = %s", item.GetKey(), txID, item.GetValue())
		results[txID] = string(item.GetValue())
	}

	return results, nil
}

// IsValidSignature take 3 arguments (creatorMSP, document, signature, certificate chain without the root certificate)
func (s *RoamingSmartContract) IsValidSignature(ctx contractapi.TransactionContextInterface, creatorMSP string, document string, signature string, certChainPEM string) error {
	log.Debugf("%s(%s, ...)", util.FunctionName(), creatorMSP)

	// get the root certificates for creatorMSP
	rootPEM, err := s.GetCertificate(ctx, creatorMSP, "root")
	if err != nil {
		// it is safe to forward local errors
		return err
	}

	// extract and verify user cert based on PEM
	userCert, err := certificate.GetVerifiedUserCertificate(rootPEM, certChainPEM)
	if err != nil {
		// it is safe to forward local errors
		return err
	}

	// decode signature from base64
	signatureBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return errorcode.CertInvalid.WithMessage("failed to decode signature string").LogReturn()
	}

	// verifies that signature is a valid signature over signed hashed data document from cert's public key
	if err = userCert.CheckSignature(userCert.SignatureAlgorithm, []byte(document), signatureBytes); err != nil {
		return errorcode.SignatureInvalid.WithMessage("signature validation failed, %v", err).LogReturn()
	}
	log.Infof("IsValidSignature: Valid")

	// document is valid
	return nil
}

// GetStorageLocation returns the storage location for
// a given storageType and key by using the composite key feature
func (s *RoamingSmartContract) GetStorageLocation(ctx contractapi.TransactionContextInterface, storageType string, key string) (string, error) {
	log.Debugf("%s(%s, %s)", util.FunctionName(), storageType, key)

	// get caller msp
	invokingMSPID, err := ctx.GetClientIdentity().GetMSPID()
	if err != nil {
		return "", errorcode.Internal.WithMessage("failed to get invoking MSP, %v", err).LogReturn()
	}

	// get the txID
	txID := ctx.GetStub().GetTxID()

	// construct the storage location
	storageLocation, err := ctx.GetStub().CreateCompositeKey(compositeKeyDefinition, []string{invokingMSPID, storageType, key, txID})

	if err != nil {
		return "", errorcode.Internal.WithMessage("failed to create composite key, %v", err).LogReturn()
	}

	log.Infof("got composite key for <%s> = 0x%s", compositeKeyDefinition, hex.EncodeToString([]byte(storageLocation)))

	return storageLocation, nil
}

// storeData stores given data with a given type on the ledger
func (s *RoamingSmartContract) storeData(ctx contractapi.TransactionContextInterface, key string, dataType string, data []byte) error {
	log.Debugf("%s(%s, %s, ...)", util.FunctionName(), key, dataType)

	// get caller msp
	invokingMSPID, err := ctx.GetClientIdentity().GetMSPID()
	if err != nil {
		return errorcode.Internal.WithMessage("failed to get invoking MSP, %v", err).LogReturn()
	}

	// fetch storage location where we will store the data
	storageLocation, err := s.GetStorageLocation(ctx, dataType, key)
	if err != nil {
		return errorcode.Internal.WithMessage("failed to fetch storageLocation, %v", err).LogReturn()
	}

	// store data
	log.Infof("will store data of type %s on ledger: state[%s] = 0x%s", dataType, storageLocation, hex.EncodeToString(data))
	err = ctx.GetStub().PutState(storageLocation, data)
	if err != nil {
		return errorcode.Internal.WithMessage("failed to store data, %v", err).LogReturn()
	}

	// fetch tx creation time
	txTimestamp, err := ctx.GetStub().GetTxTimestamp()
	if err != nil {
		return errorcode.Internal.WithMessage("failed to fetch tx creation timestamp, %v", err).LogReturn()
	}

	// build event object
	eventName := "STORE:" + dataType
	timestampString := ptypes.TimestampString(txTimestamp)

	payload := `{ ` +
		`"msp" : "` + invokingMSPID + `", ` +
		`"eventName" : "` + eventName + `", ` +
		`"timestamp" : "` + timestampString + `", ` +
		`"data" : { "storageKey" : "` + key + `" }` +
		` }`

	log.Infof("sending event %s: %s", eventName, payload)
	err = ctx.GetStub().SetEvent(eventName, []byte(payload))
	if err != nil {
		return errorcode.Internal.WithMessage("failed to send event, %v", err).LogReturn()
	}

	// no error
	return nil
}

// StoreSignature stores a given signature on the ledger
func (s *RoamingSmartContract) StoreSignature(ctx contractapi.TransactionContextInterface, key string, signatureJSON string) error {
	log.Debugf("%s(%s, ...)", util.FunctionName(), key)

	var signatureObject util.Signature
	var err error

	// try to extract all values from the given JSON
	// .signature
	signatureObject.Signature, err = util.ExtractFieldFromJSON(signatureJSON, "signature")
	if err != nil {
		// it is safe to forward local errors
		return err
	}
	// .algorithm
	signatureObject.Algorithm, err = util.ExtractFieldFromJSON(signatureJSON, "algorithm")
	if err != nil {
		// it is safe to forward local errors
		return err
	}
	// .certificate
	signatureObject.Certificate, err = util.ExtractFieldFromJSON(signatureJSON, "certificate")
	if err != nil {
		// it is safe to forward local errors
		return err
	}

	// fetch and store tx timestamp
	timestamp, err := ctx.GetStub().GetTxTimestamp()
	if err != nil {
		return errorcode.Internal.WithMessage("failed to fetch transaction timestamp").LogReturn()
	}
	signatureObject.Timestamp = ptypes.TimestampString(timestamp)

	// convert to JSON
	json, err := json.Marshal(signatureObject)
	if err != nil {
		return errorcode.Internal.WithMessage("failed to convert signatureObject to json, %v", err).LogReturn()
	}

	return s.storeData(ctx, key, "SIGNATURE", json)
}

// VerifySignatures checks all stored signature on the ledger against a document
func (s *RoamingSmartContract) VerifySignatures(ctx contractapi.TransactionContextInterface, targetMSPID string, documentID string, document string) (map[string]map[string]string, error) {
	log.Debugf("%s(%s, %s, ...)", util.FunctionName(), targetMSPID, documentID)

	var signatureObject util.Signature

	// fetch all signatures
	log.Debugf("fetching all signatures for MSP %s and documentID %s", targetMSPID, documentID)
	signatures, err := s.GetSignatures(ctx, targetMSPID, documentID)
	if err != nil {
		// it is safe to forward local errors
		return nil, err
	}

	// verify the given signatures:
	var results = make(map[string]map[string]string)
	for txID, signatureString := range signatures {
		// decode json string to object
		err := json.Unmarshal([]byte(signatureString), &signatureObject)
		if err != nil {
			return nil, errorcode.Internal.WithMessage("failed to convert signature json to object, %v", err).LogReturn()
		}

		// build result object
		results[txID] = make(map[string]string)

		// add Signature
		results[txID]["signature"] = signatureObject.Signature

		// add timestamp of signature
		results[txID]["timestamp"] = signatureObject.Timestamp

		// verify signature
		log.Debugf("tx #%s: testing signature %s...", txID, signatureObject.Signature)
		validationError := s.IsValidSignature(ctx, targetMSPID, document, signatureObject.Signature, signatureObject.Certificate)
		if validationError != nil {
			// this signature is INVALID
			results[txID]["valid"] = "false"

			// try to decode error
			errorCode, decodingError := errorcode.FromJSON(validationError)
			if decodingError != nil {
				results[txID]["errorcode"] = errorcode.BadJSON.Code
				results[txID]["message"] = decodingError.Error()
			} else {
				results[txID]["errorcode"] = errorCode.Code
				results[txID]["message"] = errorCode.Message
			}
		} else {
			// this signature is valid
			results[txID]["valid"] = "true"
			//results[txID]["errorcode"] = ""
			//results[txID]["message"] = ""
		}

		return results, nil
	}

	return nil, nil
}

// StoreDocumentHash stores a given document hash on the ledger
func (s *RoamingSmartContract) StoreDocumentHash(ctx contractapi.TransactionContextInterface, key string, documentHash string) error {
	log.Debugf("%s(%s, %s)", util.FunctionName(), key, documentHash)
	return s.storeData(ctx, key, "DOCUMENTHASH", []byte(documentHash))
}

// StorePrivateDocument will store contract Data locally
// this can be called on a remote peer or locally
// payload is a DataPayload object that contains a nonce and the payload
func (s *RoamingSmartContract) StorePrivateDocument(ctx contractapi.TransactionContextInterface, targetMSPID string, documentID string, documentBase64 string) (string, error) {
	log.Debugf("%s()", util.FunctionName())

	// verify passed data
	if len(documentID) != 64 {
		return "", errorcode.DocumentIDInvalid.WithMessage("invalid input size of documentID is invalid as %d != 64", len(documentID)).LogReturn()
	}

	// get caller msp
	invokingMSPID, err := ctx.GetClientIdentity().GetMSPID()
	if err != nil {
		return "", errorcode.Internal.WithMessage("failed to get invoking MSP, %v", err).LogReturn()
	}

	// only allow target override if called locally
	localMSPID := os.Getenv("CORE_PEER_LOCALMSPID")
	if invokingMSPID != localMSPID {
		// called from a external MSP
		if targetMSPID != localMSPID {
			// external MSP wants to set an invalid targetMSP
			return "", errorcode.NonLocalAccessDenied.LogReturn()
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
		return "", errorcode.Internal.WithMessage("failed to marshal json").LogReturn()
	}

	// fetch the configured rest endpoint
	uri, err := s.getLocalOffchainDBConfig(ctx)
	if err != nil {
		return "", errorcode.OffchainDBConfig.WithMessage("failed to fetch OffchainDB uri, %v", err).LogReturn()
	}

	// store data in offchain db
	storedDataHash, err := util.OffchainDatabaseStore(uri, documentID, document)
	if err != nil {
		return "", errorcode.Internal.WithMessage("failed to store data, %v", err).LogReturn()
	}

	log.Infof("stored data ok. saved data hash %s", storedDataHash)

	// verify that the hash from the post request matches our data
	if dataHash != storedDataHash {
		return "", errorcode.Internal.WithMessage("hash mismatch %s != %s", dataHash, storedDataHash).LogReturn()
	}

	return storedDataHash, nil
}

// FetchPrivateDocument will return a private document identified by its documentID
// ACL restricted to local queries only
func (s *RoamingSmartContract) FetchPrivateDocument(ctx contractapi.TransactionContextInterface, documentID string) (string, error) {
	log.Debugf("%s(%s)", util.FunctionName(), documentID)

	// ACL restricted to local queries only
	if !acl.LocalCall(ctx) {
		return "", errorcode.NonLocalAccessDenied.LogReturn()
	}

	log.Infof("accessing private document with id " + documentID)

	// fetch the configured rest endpoint
	uri, err := s.getLocalOffchainDBConfig(ctx)
	if err != nil {
		return "", errorcode.OffchainDBConfig.WithMessage("failed to fetch OffchainDB uri, %v", err).LogReturn()
	}

	// fetch from database
	data, err := util.OffchainDatabaseFetch(uri, documentID)
	if err != nil {
		return "", errorcode.DocumentIDUnknown.WithMessage("db access failed, %v", err).LogReturn()
	}

	// convert to clean json without couchdb "leftovers"
	dataJSON, err := data.MarshalToCleanJSON()
	if err != nil {
		return "", errorcode.Internal.WithMessage("failed to convert data from db to json, %v", err).LogReturn()
	}

	// return result
	return string(dataJSON), nil
}

// DeletePrivateDocument will delete a private document identified by its documentID from the database
// ACL restricted to local queries only
func (s *RoamingSmartContract) DeletePrivateDocument(ctx contractapi.TransactionContextInterface, documentID string) error {
	log.Debugf("%s(%s)", util.FunctionName(), documentID)

	// ACL restricted to local queries only
	if !acl.LocalCall(ctx) {
		return errorcode.NonLocalAccessDenied.LogReturn()
	}

	log.Infof("deleting private document with id " + documentID)

	// fetch the configured rest endpoint
	uri, err := s.getLocalOffchainDBConfig(ctx)
	if err != nil {
		return errorcode.OffchainDBConfig.WithMessage("failed to fetch OffchainDB uri, %v", err).LogReturn()
	}

	// fetch from database
	err = util.OffchainDatabaseDelete(uri, documentID)
	if err != nil {
		return errorcode.Internal.WithMessage("db delete access failed, %v", err).LogReturn()
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
		return "", errorcode.NonLocalAccessDenied.LogReturn()
	}

	// fetch the configured rest endpoint
	uri, err := s.getLocalOffchainDBConfig(ctx)
	if err != nil {
		return "", errorcode.OffchainDBConfig.WithMessage("failed to fetch offchaindb uri, %v", err).LogReturn()
	}

	// fetch from database
	ids, err := util.OffchainDatabaseFetchAllDocumentIDs(uri)
	if err != nil {
		return "", errorcode.Internal.WithMessage("db access failed, %v", err).LogReturn()
	}

	// convert array to json
	json, err := json.Marshal(ids)
	if err != nil {
		return "", errorcode.Internal.WithMessage("failed to convert document IDs to json, %v", err).LogReturn()
	}

	return string(json), nil
}
