package contract

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"hybrid/acl"
	"hybrid/certificate"
	"hybrid/errorcode"
	"hybrid/util"
	"os"
	"time"

	"github.com/golang/protobuf/ptypes"
	"github.com/hyperledger/fabric-contract-api-go/contractapi"
	log "github.com/sirupsen/logrus"
)

const compositeKeyDefinition string = "owner~type~key~txid"

// RoamingSmartContract creates a new hlf contract api
type RoamingSmartContract struct {
	contractapi.Contract
}

var contract *RoamingSmartContract

func InitRoamingSmartContract() *RoamingSmartContract {
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
	log.Debugf("%s()", util.FunctionName(1))

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
	log.Debugf("%s()", util.FunctionName(1))

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
	log.Debugf("%s()", util.FunctionName(1))

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
	log.Debugf("%s(%s, ...)", util.FunctionName(1), certType)

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
	log.Debugf("%s(%s, %s)", util.FunctionName(1), msp, certType)

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

	log.Debugf("%s(...) got cert %s, ", util.FunctionName(1), string(certData))
	log.Debugf("%s(...) got cert %s, ", util.FunctionName(0), string(certData))

	// all fine
	return string(certData), nil
}

// GetEvaluateTransactions returns functions of RoamingSmartContract to be tagged as evaluate (=query)
// see https://godoc.org/github.com/hyperledger/fabric-contract-api-go/contractapi#SystemContract.GetEvaluateTransactions
// note: this is just a hint for the caller, this is not taken into account during invocation
func (s *RoamingSmartContract) GetEvaluateTransactions() []string {
	return []string{
		"GetOffchainDBConfig",
		"GetCertificate",
		"CreateStorageKey",
		"CreateReferenceID",
		"CreateReferencePayloadLink",
		"GetReferencePayloadLink",
		"GetSignatures",
		"IsValidSignature",
		"GetStorageLocation",
		"PublishReferencePayloadLink",
		"StorePrivateDocument",
		"FetchPrivateDocument",
		"FetchPrivateDocumentReferenceIDs",
	}
}

// CreateReferenceID creates a referenceID and verifies that is has not been used yet
func (s *RoamingSmartContract) CreateReferenceID(ctx contractapi.TransactionContextInterface) (string, error) {
	log.Debugf("%s()", util.FunctionName(1))

	// TODO: verify that the golang crypto lib returns random numbers that are good enough to be used here!
	rand32 := make([]byte, 32)
	_, err := rand.Read(rand32)
	if err != nil {
		return "", errorcode.Internal.WithMessage("failed to generate referenceID, %v", err).LogReturn()
	}

	// encode random numbers to hex string
	referenceID := hex.EncodeToString(rand32)

	// get caller msp
	invokingMSPID, err := ctx.GetClientIdentity().GetMSPID()
	if err != nil {
		return "", errorcode.Internal.WithMessage("failed to get invoking MSP, %v", err).LogReturn()
	}

	// make sure that there is no such referenceID for this MSP on the ledger yet:
	storageKey, err := s.CreateStorageKey(invokingMSPID, referenceID)
	if err != nil {
		// it is safe to return local errors
		return "", err
	}

	data, err := ctx.GetStub().GetState(storageKey)
	if err != nil {
		return "", errorcode.Internal.WithMessage("unable to get ledger state, %v", err).LogReturn()
	}

	if data != nil {
		return "", errorcode.ReferenceIDExists.WithMessage("data for this referenceID %s already exists", referenceID).LogReturn()
	}

	// fine, data does not exist on ledger -> the calulated referenceID is ok
	return referenceID, nil
}

// CreateStorageKey returns the hidden key used for hidden communication based on a referenceID and the targetMSP
func (s *RoamingSmartContract) CreateStorageKey(targetMSPID string, referenceID string) (string, error) {
	log.Debugf("%s(%s, %s)", util.FunctionName(1), targetMSPID, referenceID)

	if len(referenceID) != 64 {
		return "", errorcode.ReferenceIDInvalid.WithMessage("invalid input size of referenceID is invalid as %d != 64", len(referenceID)).LogReturn()
	}

	if len(targetMSPID) == 0 {
		return "", errorcode.TargetMSPInvalid.WithMessage("invalid input, targetMSPID is empty").LogReturn()
	}

	hashInput := util.HashConcat(targetMSPID, referenceID)
	storageKey := util.CalculateHash(hashInput)

	return storageKey, nil
}

func (s *RoamingSmartContract) verifyReferencePayloadLink(ctx contractapi.TransactionContextInterface, creatorMSPID string, referenceID string, payloadHash string) (bool, error) {
	log.Debugf("%s(%s, %s, %s)", util.FunctionName(1), creatorMSPID, referenceID, payloadHash)

	// ACL restricted to local queries only
	if !acl.LocalCall(ctx) {
		return false, errorcode.NonLocalAccessDenied.LogReturn()
	}

	// fetch data published on ledger
	ledgerPayloadLink, err := s.GetReferencePayloadLink(ctx, creatorMSPID, referenceID)
	if err != nil {
		return false, err
	}

	// calculate expeced data based on payload hash
	expectedPayloadLink := util.CalculateHash(util.HashConcat(referenceID, payloadHash))

	// verify ledger matches the payloadhash
	if expectedPayloadLink == ledgerPayloadLink {
		// all fine!
		return true, nil
	}

	// something failed
	return false, nil
}

// CreateReferencePayloadLink returns the reference and payload link based on a referenceID and the payloadHash
func (s *RoamingSmartContract) CreateReferencePayloadLink(referenceID string, payloadHash string) ([2]string, error) {
	log.Debugf("%s(%s, %s)", util.FunctionName(1), referenceID, payloadHash)

	if len(referenceID) != 64 {
		return [2]string{"", ""}, errorcode.ReferenceIDInvalid.WithMessage("invalid input size of referenceID is invalid as %d != 64", len(referenceID)).LogReturn()
	}

	referenceKey := util.CalculateHash(referenceID)
	referenceValue := util.CalculateHash(util.HashConcat(referenceID, payloadHash))

	log.Debugf("%s(...) referenceKey   = %s", util.FunctionName(1), referenceKey)
	log.Debugf("hash in: %s", util.HashConcat(referenceID, payloadHash))
	log.Debugf("%s(...) referenceValue = %s", util.FunctionName(1), referenceValue)
	return [2]string{referenceKey, referenceValue}, nil
}

// getStorageLocationData returns the stored data for a given storage type and key
func (s *RoamingSmartContract) getStorageLocationData(ctx contractapi.TransactionContextInterface, targetMSPID, storageType, storageKey string) (map[string]string, error) {
	log.Debugf("%s(%s, %s, %s)", util.FunctionName(1), targetMSPID, storageType, storageKey)

	// query results for composite key without identity
	iterator, err := ctx.GetStub().GetStateByPartialCompositeKey(compositeKeyDefinition, []string{targetMSPID, storageType, storageKey})

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

// GetSignatures returns all signatures stored in the ledger for this key
func (s *RoamingSmartContract) GetSignatures(ctx contractapi.TransactionContextInterface, targetMSPID string, key string) (map[string]string, error) {
	log.Debugf("%s(%s, %s)", util.FunctionName(1), targetMSPID, key)

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

// IsValidSignature verifies if a signature is valid based on the the signaturePayload, the certChain, and the signature
func (s *RoamingSmartContract) IsValidSignature(ctx contractapi.TransactionContextInterface, creatorMSPID, signaturePayload, signature, certChainPEM string) error {
	log.Debugf("%s(%s, ..., %s)", util.FunctionName(1), signature, signaturePayload)

	// get the root certificates for creatorMSP
	rootPEM, err := s.GetCertificate(ctx, creatorMSPID, "root")
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

	//log.Infof("> checking signaturePayload %s", signaturePayload)
	//log.Infof("> checking signature %s", signatureBytes)

	// verifies that signature is a valid signature
	if err = userCert.CheckSignature(userCert.SignatureAlgorithm, []byte(signaturePayload), signatureBytes); err != nil {
		return errorcode.SignatureInvalid.WithMessage("signature validation failed, %v", err).LogReturn()
	}
	log.Infof("IsValidSignature: Valid")

	// document is valid
	return nil
}

// GetStorageLocation returns the storage location for
// a given storageType and key by using the composite key feature
func (s *RoamingSmartContract) GetStorageLocation(ctx contractapi.TransactionContextInterface, storageType string, key string) (string, error) {
	log.Debugf("%s(%s, %s)", util.FunctionName(1), storageType, key)

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
func (s *RoamingSmartContract) storeData(ctx contractapi.TransactionContextInterface, key string, dataType string, data []byte) (string, error) {
	log.Debugf("%s(%s, %s, ...)", util.FunctionName(1), key, dataType)

	// get caller msp
	invokingMSPID, err := ctx.GetClientIdentity().GetMSPID()
	if err != nil {
		return "", errorcode.Internal.WithMessage("failed to get invoking MSP, %v", err).LogReturn()
	}

	// fetch storage location where we will store the data
	storageLocation, err := s.GetStorageLocation(ctx, dataType, key)
	if err != nil {
		return "", errorcode.Internal.WithMessage("failed to fetch storageLocation, %v", err).LogReturn()
	}

	// store data
	log.Infof("will store data of type %s on ledger: state[%s] = 0x%s", dataType, storageLocation, hex.EncodeToString(data))
	err = ctx.GetStub().PutState(storageLocation, data)
	if err != nil {
		return "", errorcode.Internal.WithMessage("failed to store data, %v", err).LogReturn()
	}

	// fetch tx creation time
	txTimestamp, err := ctx.GetStub().GetTxTimestamp()
	if err != nil {
		return "", errorcode.Internal.WithMessage("failed to fetch tx creation timestamp, %v", err).LogReturn()
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
		return "", errorcode.Internal.WithMessage("failed to send event, %v", err).LogReturn()
	}

	// no error
	return timestampString, nil
}

// PublishReferencePayloadLink stores a given document hash on the ledger
func (s *RoamingSmartContract) PublishReferencePayloadLink(ctx contractapi.TransactionContextInterface, key string, value string) (string, error) {
	log.Debugf("%s()", util.FunctionName(1))
	return s.storeData(ctx, key, "PAYLOADLINK", []byte(value))
}

// StoreSignature stores a given signature on the ledger
func (s *RoamingSmartContract) StoreSignature(ctx contractapi.TransactionContextInterface, storageKey string, signatureJSON string) (string, error) {
	log.Debugf("%s(%s, ...)", util.FunctionName(1), storageKey)

	var signatureObject util.Signature
	var err error

	// try to extract all values from the given JSON
	// .signature
	signatureObject.Signature, err = util.ExtractFieldFromJSON(signatureJSON, "signature")
	if err != nil {
		// it is safe to forward local errors
		return "", err
	}
	// .algorithm
	signatureObject.Algorithm, err = util.ExtractFieldFromJSON(signatureJSON, "algorithm")
	if err != nil {
		// it is safe to forward local errors
		return "", err
	}
	// .certificate
	signatureObject.Certificate, err = util.ExtractFieldFromJSON(signatureJSON, "certificate")
	if err != nil {
		// it is safe to forward local errors
		return "", err
	}

	// Check if the certificate was used for signing before
	certificateExists, err := s.signatureExistsForCallerCertificate(ctx, signatureObject.Certificate, storageKey)
	if err != nil {
		// it is safe to forward local errors
		return "", err
	}
	if certificateExists {
		return "", errorcode.CertAlreadyExists.WithMessage("certificate was used for signing already").LogReturn()
	}

	// fetch and store tx timestamp
	timestamp, err := ctx.GetStub().GetTxTimestamp()
	if err != nil {
		return "", errorcode.Internal.WithMessage("failed to fetch transaction timestamp").LogReturn()
	}
	signatureObject.Timestamp = ptypes.TimestampString(timestamp)

	// convert to JSON
	json, err := util.MarshalLowerCamelcaseJSON(signatureObject)
	if err != nil {
		return "", errorcode.Internal.WithMessage("failed to convert signatureObject to json, %v", err).LogReturn()
	}

	return s.storeData(ctx, storageKey, "SIGNATURE", json)
}

func (s *RoamingSmartContract) signatureExistsForCallerCertificate(ctx contractapi.TransactionContextInterface, certificate string, storageKey string) (bool, error) {
	// get caller msp
	invokingMSPID, err := ctx.GetClientIdentity().GetMSPID()
	if err != nil {
		return false, errorcode.Internal.WithMessage("failed to get invoking MSP, %v", err).LogReturn()
	}

	// get all signatures stored for at storage key
	currentSignatures, err := s.GetSignatures(ctx, invokingMSPID, storageKey)
	if err != nil {
		// it is safe to forward local errors
		return false, err
	}

	// check if certificate was used for signing already
	for _, storedSignature := range currentSignatures {
		storedCertificate, err := util.ExtractFieldFromJSON(storedSignature, "certificate")
		if err != nil {
			// it is safe to forward local errors
			return false, err
		}
		if storedCertificate == certificate {
			return true, nil
		}
	}

	return false, nil
}

// Get the referencePayloadLink
// ACL restricted to local queries only
func (s *RoamingSmartContract) GetReferencePayloadLink(ctx contractapi.TransactionContextInterface, creatorMSPID string, referenceID string) (string, error) {
	log.Debugf("%s(%s, %s)", util.FunctionName(1), creatorMSPID, referenceID)

	// ACL restricted to local queries only
	if !acl.LocalCall(ctx) {
		return "", errorcode.NonLocalAccessDenied.LogReturn()
	}

	// fetch reference payload link
	referencePayloadLink := util.CalculateHash(referenceID)
	log.Debugf("%s() got reference payload link key %s", util.FunctionName(1), referencePayloadLink)

	// fetch reference payload link value stored by the creator
	storedData, err := s.getStorageLocationData(ctx, creatorMSPID, "PAYLOADLINK", referencePayloadLink)
	if err != nil {
		// it is safe to forward local errors
		return "", err
	}

	// check if there is no document
	if len(storedData) != 1 {
		return "", errorcode.PayloadLinkMissing.WithMessage("expected 1, got %d payloadlinks (referenceID %s)", len(storedData), referenceID).LogReturn()
	}

	// extract the stored hash, the check above made sure that there is only one entry
	referencePayloadLinkValue := ""
	for _, value := range storedData {
		referencePayloadLinkValue = value
	}
	if referencePayloadLinkValue == "" {
		return "", errorcode.Internal.WithMessage("failed to get reference payload link value").LogReturn()
	}

	// done, fetched link
	return referencePayloadLinkValue, nil
}

// VerifySignatures checks all stored signature on the ledger against a document
// referenceID  = the referenceID tying everything together
// creatorMSPID = MSP that created the contract initially
// targetMSPID  = MSP whose signatures to check
// ACL restricted to local queries only
func (s *RoamingSmartContract) VerifySignatures(ctx contractapi.TransactionContextInterface, referenceID, creatorMSPID, targetMSPID string) (map[string]map[string]string, error) {
	log.Debugf("%s(%s, %s, %s, ...)", util.FunctionName(1), creatorMSPID, targetMSPID, referenceID)

	// ACL restricted to local queries only
	if !acl.LocalCall(ctx) {
		return nil, errorcode.NonLocalAccessDenied.LogReturn()
	}

	var signatureObject util.Signature

	// fetch storage keys for signature and document hash
	storageKeySignature, err := s.CreateStorageKey(targetMSPID, referenceID)
	if err != nil {
		//it is safe to forward local errors
		return nil, err
	}
	log.Debugf("%s() got signature storage key %s", util.FunctionName(1), storageKeySignature)

	// fetch all signatures
	log.Debugf("fetching all signatures for storageKey %s", storageKeySignature)
	signatures, err := s.GetSignatures(ctx, targetMSPID, storageKeySignature)
	if err != nil {
		// it is safe to forward local errors
		return nil, err
	}

	// fetch reference payload link
	referencePayloadLink, err := s.GetReferencePayloadLink(ctx, creatorMSPID, referenceID)
	if err != nil {
		// it is safe to forward local errors
		return nil, err
	}

	// verify the given signatures:
	var results = make(map[string]map[string]string)
	for txID, signatureString := range signatures {
		// decode json string to object
		err := util.UnmarshalLowerCamelcaseJSON([]byte(signatureString), &signatureObject)
		if err != nil {
			return nil, errorcode.Internal.WithMessage("failed to convert signature json to object, %v", err).LogReturn()
		}

		// build result object
		results[txID] = make(map[string]string)

		// add Signature
		results[txID]["signature"] = signatureObject.Signature

		// add algorithm
		results[txID]["algorithm"] = signatureObject.Algorithm

		// add certificate
		results[txID]["certificate"] = signatureObject.Certificate

		// add timestamp of signature
		results[txID]["timestamp"] = signatureObject.Timestamp

		// reconstruct signature payload
		signaturePayload := util.CalculateHash(util.HashConcat(targetMSPID, referenceID, referencePayloadLink))
		log.Debugf("%s() signaturePayload is %s", util.FunctionName(1), signaturePayload)

		// verify signature
		log.Debugf("tx #%s: testing signature %s...", txID, signatureObject.Signature)
		validationError := s.IsValidSignature(ctx, targetMSPID, signaturePayload, signatureObject.Signature, signatureObject.Certificate)
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

// StorePrivateDocument will store contract Data locally
// this can be called on a remote peer or locally
// payload is a DataPayload object that contains a nonce and the payload
func (s *RoamingSmartContract) StorePrivateDocument(ctx contractapi.TransactionContextInterface, targetMSPID string, referenceID string, payload string) (string, error) {
	log.Debugf("%s()", util.FunctionName(1))

	// verify passed data
	if len(referenceID) != 64 {
		return "", errorcode.ReferenceIDInvalid.WithMessage("invalid input size of referenceID is invalid as %d != 64", len(referenceID)).LogReturn()
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
	payloadHash := util.CalculateHash(payload)

	// create rest struct
	var document = util.OffchainData{}
	document.FromMSP = invokingMSPID
	document.ToMSP = targetMSPID
	document.Payload = payload
	document.PayloadHash = payloadHash
	document.ReferenceID = referenceID
	// DO NOT store
	// document.BlockchainRef.*
	// as it is not available yet

	if err != nil {
		return "", errorcode.Internal.WithMessage("failed to marshal json").LogReturn()
	}

	// fetch the configured rest endpoint
	uri, err := s.getLocalOffchainDBConfig(ctx)
	if err != nil {
		return "", errorcode.OffchainDBConfig.WithMessage("failed to fetch OffchainDB uri, %v", err).LogReturn()
	}

	// store data in offchain db
	storedPayloadHash, err := util.OffchainDatabaseStore(uri, referenceID, document)
	if err != nil {
		return "", errorcode.Internal.WithMessage("failed to store data, %v", err).LogReturn()
	}

	log.Infof("stored data ok. saved data hash %s", storedPayloadHash)

	// verify that the hash from the post request matches our data
	if payloadHash != storedPayloadHash {
		return "", errorcode.Internal.WithMessage("hash mismatch %s != %s", payloadHash, storedPayloadHash).LogReturn()
	}

	return storedPayloadHash, nil
}

// Fetch a blockchain ref for a given referenceID
// ACL restricted to local queries only
func (s *RoamingSmartContract) fetchBlockchainRef(ctx contractapi.TransactionContextInterface, creatorMSPID string, referenceID string) (*util.BlockchainRef, error) {
	log.Debugf("%s(%s, %s)", util.FunctionName(1), creatorMSPID, referenceID)

	var result = util.BlockchainRef{}

	// type is fixed hlf for now
	result.Type = `hlf`

	// fetch reference payload link
	referencePayloadLink := util.CalculateHash(referenceID)
	log.Debugf("%s() got reference payload link key %s", util.FunctionName(1), referencePayloadLink)

	// fetch reference payload link value stored by the creator
	storedData, err := s.getStorageLocationData(ctx, creatorMSPID, "PAYLOADLINK", referencePayloadLink)
	if err != nil {
		return nil, err
	}

	if len(storedData) != 1 {
		return nil, errorcode.PayloadLinkMissing.WithMessage("expected 1, got %d payloadlinks (referenceID %s)", len(storedData), referenceID).LogReturn()
	}

	// txID can be extracted from the storagelocation result
	for txID := range storedData {
		// as we previously checked that this has exactly one element, this is safe to do:
		result.TxID = txID
		break
	}

	// the tx timestamp can be fetched from the ledger
	// note: this requires core.ledger.history.enableHistoryDatabase = true !
	storedKey, err := ctx.GetStub().CreateCompositeKey(compositeKeyDefinition, []string{creatorMSPID, "PAYLOADLINK", referencePayloadLink, result.TxID})
	if err != nil {
		return nil, errorcode.Internal.WithMessage("failed to get create composite key, %v", err).LogReturn()
	}

	historyIterator, err := ctx.GetStub().GetHistoryForKey(storedKey)
	if err != nil {
		return nil, errorcode.Internal.WithMessage("failed to get tx history for key %s, %v", storedKey, err).LogReturn()
	}
	defer historyIterator.Close()

	// results should be exactly one entry!
	if !historyIterator.HasNext() {
		// no entry?!
		return nil, errorcode.Internal.WithMessage("no tx history for txID %s. Please set core.ledger.history.enableHistoryDatabase=true!", result.TxID).LogReturn()
	}

	// fetch transaction from history
	tx, err := historyIterator.Next()
	if err != nil {
		return nil, errorcode.Internal.WithMessage("failed to get tx history, %v", err).LogReturn()
	}
	result.Timestamp = time.Unix(tx.GetTimestamp().Seconds, int64(tx.GetTimestamp().Nanos)).Format(time.RFC3339)

	// are there more entries?
	if historyIterator.HasNext() {
		return nil, errorcode.Internal.WithMessage("to many history entries for txID %s. this is really bad!", result.TxID).LogReturn()
	}

	// all fine
	return &result, nil
}

// FetchPrivateDocument will return a private document identified by its referenceID
// ACL restricted to local queries only
func (s *RoamingSmartContract) FetchPrivateDocument(ctx contractapi.TransactionContextInterface, referenceID string) (string, error) {
	log.Debugf("%s(%s)", util.FunctionName(1), referenceID)

	// ACL restricted to local queries only
	if !acl.LocalCall(ctx) {
		return "", errorcode.NonLocalAccessDenied.LogReturn()
	}

	log.Infof("accessing private document with referenceID " + referenceID)

	// fetch the configured rest endpoint
	uri, err := s.getLocalOffchainDBConfig(ctx)
	if err != nil {
		return "", errorcode.OffchainDBConfig.WithMessage("failed to fetch OffchainDB uri, %v", err).LogReturn()
	}

	// fetch from database
	data, err := util.OffchainDatabaseFetch(uri, referenceID)
	if err != nil {
		return "", errorcode.ReferenceIDUnknown.WithMessage("db access failed, %v", err).LogReturn()
	}

	// re-verify data hash:
	expectedPayloadHash := util.CalculateHash(data.Payload)
	payloadHash := data.PayloadHash
	if payloadHash != expectedPayloadHash {
		return "", errorcode.Internal.WithMessage("hash mismatch %s != %s", payloadHash, expectedPayloadHash).LogReturn()
	}

	// check if this document matches to what was published on the ledger
	referencePayloadLinkValid, err := s.verifyReferencePayloadLink(ctx, data.FromMSP, referenceID, expectedPayloadHash)
	if err != nil {
		// it is safe to forward local errors
		return "", err
	}

	if !referencePayloadLinkValid {
		return "", errorcode.PayloadLinkInvalid.WithMessage("failed to verify payloadlink on ledger").LogReturn()
	}

	// nice, this document contains the main fields
	// let's add the blockchain reference stuff
	blockchainRef, err := s.fetchBlockchainRef(ctx, data.FromMSP, referenceID)
	if err != nil {
		return "", err
	}
	data.BlockchainRef = *blockchainRef

	// convert to clean json without couchdb "leftovers"
	dataJSON, err := data.MarshalToCleanJSON()
	if err != nil {
		return "", errorcode.Internal.WithMessage("failed to convert data from db to json, %v", err).LogReturn()
	}

	// return result
	return string(dataJSON), nil
}

// DeletePrivateDocument will delete a private document identified by its referenceID from the database
// ACL restricted to local queries only
func (s *RoamingSmartContract) DeletePrivateDocument(ctx contractapi.TransactionContextInterface, referenceID string) error {
	log.Debugf("%s()", util.FunctionName(1))

	// ACL restricted to local queries only
	if !acl.LocalCall(ctx) {
		return errorcode.NonLocalAccessDenied.LogReturn()
	}

	log.Infof("deleting private document with referenceID " + referenceID)

	// fetch the configured rest endpoint
	uri, err := s.getLocalOffchainDBConfig(ctx)
	if err != nil {
		return errorcode.OffchainDBConfig.WithMessage("failed to fetch OffchainDB uri, %v", err).LogReturn()
	}

	// fetch from database
	err = util.OffchainDatabaseDelete(uri, referenceID)
	if err != nil {
		return errorcode.Internal.WithMessage("db delete access failed, %v", err).LogReturn()
	}

	// all fine
	return nil
}

// FetchPrivateDocumentReferenceIDs will return a list of referenceIDs of the private documents
// ACL restricted to local queries only
func (s *RoamingSmartContract) FetchPrivateDocumentReferenceIDs(ctx contractapi.TransactionContextInterface) (string, error) {
	log.Debugf("%s()", util.FunctionName(1))

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
	ids, err := util.OffchainDatabaseFetchAllReferenceIDs(uri)
	if err != nil {
		return "", errorcode.Internal.WithMessage("db access failed, %v", err).LogReturn()
	}

	// convert array to json
	json, err := util.MarshalLowerCamelcaseJSON(ids)
	if err != nil {
		return "", errorcode.Internal.WithMessage("failed to convert referenceIDs to json, %v", err).LogReturn()
	}

	return string(json), nil
}