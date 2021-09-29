// SPDX-FileCopyrightText: 2021 GSMA and all contributors.
// SPDX-License-Identifier: Apache-2.0
package contract

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
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

const expectedIDLength = 64

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

// CheckOffchainDBConfig returns if the database is configured and reachable
func (s *RoamingSmartContract) CheckOffchainDBConfig(ctx contractapi.TransactionContextInterface) error {
	log.Debugf("%s()", util.FunctionName(1))

	// fetch the configured rest endpoint
	uri, err := s.getLocalOffchainDBConfig(ctx)
	if err != nil {
		// DO NOT return the actual error here as this is not ACL restricted and can be called by world!
		log.Error(err)
		return errorcode.OffchainDBConfig.WithMessage("failed to fetch OffchainDB uri").LogReturn()
	}

	err = util.OffchainDatabaseCheck(uri)
	if err != nil {
		// DO NOT return the actual error here as this is not ACL restricted and can be called by world!
		log.Error(err)
		return errorcode.Internal.WithMessage("offchaindb check failed").LogReturn()
	}

	// all fine
	return nil
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

// GetCertificate retrieves the certificate for a given organization from the ledger and checks validity for the current time
func (s *RoamingSmartContract) GetCertificate(ctx contractapi.TransactionContextInterface, msp string, certType string) (string, error) {
	return s.GetCertificateValidAtTime(ctx, msp, certType, time.Now())
}

// GetCertificate retrieves the certificate for a given organization from the ledger and checks validity at a given time
func (s *RoamingSmartContract) GetCertificateValidAtTime(ctx contractapi.TransactionContextInterface, msp string, certType string, atTime time.Time) (string, error) {
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

	if len(certData) > 0 {
		// filter revoked certificates from the set of root certs
		certData, err = certificate.FilterRevokedRootCertificates(ctx, msp, certData, atTime)
		if err != nil {
			return "", err
		}
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
		"CheckOffchainDBConfig",
		"GetCertificate",
		"CreateStorageKey",
		"CreateReferenceID",
		"CreateReferencePayloadLink",
		"GetReferencePayloadLink",
		"GetSignatures",
		"IsValidSignature",
		"IsValidSignatureAtTime",
		"GetStorageLocation",
		"PublishReferencePayloadLink",
		"StorePrivateDocument",
		"SubmitCRL",
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

	// fine, data does not exist on ledger -> the calculated referenceID is ok
	return referenceID, nil
}

// CreateStorageKey returns the hidden key used for hidden communication based on a referenceID and the targetMSP
func (s *RoamingSmartContract) CreateStorageKey(targetMSPID string, referenceID string) (string, error) {
	log.Debugf("%s(%s, %s)", util.FunctionName(1), targetMSPID, referenceID)

	if len(referenceID) != expectedIDLength {
		return "", errorcode.ReferenceIDInvalid.WithMessage("invalid input size of referenceID is invalid as %d != %d", len(referenceID), expectedIDLength).LogReturn()
	}

	if len(targetMSPID) == 0 {
		return "", errorcode.TargetMSPInvalid.WithMessage("invalid input, targetMSPID is empty").LogReturn()
	}

	hashInput := util.HashConcat(targetMSPID, referenceID)
	storageKey := util.CalculateHash(hashInput)

	return storageKey, nil
}

func (s *RoamingSmartContract) verifyReferencePayloadLink(ctx contractapi.TransactionContextInterface, referenceID string, payloadHash string) (bool, error) {
	log.Debugf("%s(%s, %s)", util.FunctionName(1), referenceID, payloadHash)

	// ACL restricted to local queries only
	if !acl.LocalCall(ctx) {
		return false, errorcode.NonLocalAccessDenied.LogReturn()
	}

	// fetch data published on ledger
	ledgerPayloadLink, err := s.GetReferencePayloadLink(ctx, referenceID)
	if err != nil {
		return false, err
	}

	// calculate expected data based on payload hash
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

	if len(referenceID) != expectedIDLength {
		return [2]string{"", ""}, errorcode.ReferenceIDInvalid.WithMessage("invalid input size of referenceID is invalid as %d != %d", len(referenceID), expectedIDLength).LogReturn()
	}

	referenceKey := util.CalculateHash(referenceID)
	referenceValue := util.CalculateHash(util.HashConcat(referenceID, payloadHash))

	log.Debugf("%s(...) referenceKey   = %s", util.FunctionName(1), referenceKey)
	log.Debugf("hash in: %s", util.HashConcat(referenceID, payloadHash))
	log.Debugf("%s(...) referenceValue = %s", util.FunctionName(1), referenceValue)

	return [2]string{referenceKey, referenceValue}, nil
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

// IsValidSignature checks if a signature is valid and returns an error otherwise
// Uses current time, it checks if any certificate in the chain has been revoked
// Checks the validity of the cert chain
func (s *RoamingSmartContract) IsValidSignature(ctx contractapi.TransactionContextInterface, signerMSPID, signaturePayload, signature, signatureAlgorithm, certChainPEM string) error {
	nowBytes, err := time.Now().MarshalText()
	if err != nil {
		return errorcode.Internal.WithMessage("failed marshalling current time, %s", err).LogReturn()
	}
	return s.IsValidSignatureAtTime(ctx, signerMSPID, signaturePayload, signature, signatureAlgorithm, certChainPEM, string(nowBytes))
}

// IsValidSignature verifies if a signature is valid based on the the signaturePayload, the certChain, and the signature
func (s *RoamingSmartContract) IsValidSignatureAtTime(ctx contractapi.TransactionContextInterface, signerMSPID, signaturePayload, signature, signatureAlgorithm, certChainPEM, atTimeString string) error {
	log.Debugf("%s(%s, ..., %s)", util.FunctionName(1), signature, signaturePayload)

	atTime, err := time.Parse(time.RFC3339, atTimeString)
	if err != nil {
		return errorcode.BadTimeFormat.WithMessage("failed unmarshalling time, %s", err).LogReturn()
	}

	// extract and verify user cert based on PEM
	userCert, err := s.getUserCertFromCertificateChain(ctx, signerMSPID, certChainPEM, atTime)
	if err != nil {
		// it is safe to forward local errors
		return err
	}

	// decode signature from base64
	signatureBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return errorcode.SignatureInvalid.WithMessage("failed to decode signature string").LogReturn()
	}

	x509signatureAlgorithm, err := certificate.GetSignatureAlgorithmFromString(signatureAlgorithm)
	if err != nil {
		// it is safe to forward local errors
		return err
	}

	//log.Infof("> checking signaturePayload %s", signaturePayload)
	//log.Infof("> checking signature %s", signatureBytes)

	// verifies that signature is a valid signature
	if err = userCert.CheckSignature(x509signatureAlgorithm, []byte(signaturePayload), signatureBytes); err != nil {
		return errorcode.SignatureInvalid.WithMessage("signature validation failed, %v", err).LogReturn()
	}

	log.Infof("IsValidSignature: Valid")

	// document is valid
	return nil
}

// getUserCertFromCertificateChain verifies if the cert chain is valid, derived from a stored root cert and returnes the user cert
func (s *RoamingSmartContract) getUserCertFromCertificateChain(ctx contractapi.TransactionContextInterface, creatorMSPID, certChainPEM string, atTime time.Time) (*x509.Certificate, error) {
	// get the root certificates for creatorMSP
	rootPEM, err := s.GetCertificateValidAtTime(ctx, creatorMSPID, "root", atTime)
	if err != nil {
		// it is safe to forward local errors
		return nil, err
	}

	// extract and verify user cert based on PEM
	return certificate.GetVerifiedUserCertificate(ctx, creatorMSPID, rootPEM, certChainPEM, atTime)
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

	// emit event
	timestampString, err := s.emitStorageEvent(ctx, dataType, key)
	if err != nil {
		// it is safe to forward local errors
		return "", err
	}

	// no error
	return timestampString, nil
}

// emitStorageEvent emits an event to inform subscribers that new data was stored
func (s *RoamingSmartContract) emitStorageEvent(ctx contractapi.TransactionContextInterface, dataType string, key string) (string, error) {
	// get caller msp
	invokingMSPID, err := ctx.GetClientIdentity().GetMSPID()
	if err != nil {
		return "", errorcode.Internal.WithMessage("failed to get invoking MSP, %v", err).LogReturn()
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

	return timestampString, nil
}

// PublishReferencePayloadLink stores a given document hash on the ledger
func (s *RoamingSmartContract) PublishReferencePayloadLink(ctx contractapi.TransactionContextInterface, key string, value string) (string, error) {
	log.Debugf("%s()", util.FunctionName(1))

	var err error

	// Check if a Payload Link was already stored at the given key
	storedValue, err := ctx.GetStub().GetState(key)
	if err != nil {
		return "", errorcode.Internal.WithMessage("failed to check if payload link is already present %v", err).LogReturn()
	}

	if storedValue != nil {
		return "", errorcode.PayloadLinkExists.WithMessage("data was found at the given key, cannot overwrite present payloadlinks %v", err).LogReturn()
	}

	// store payload link
	log.Infof("will store payload link on ledger, key: %s , value: %s ", key, value)

	err = ctx.GetStub().PutState(key, []byte(value))
	if err != nil {
		return "", errorcode.Internal.WithMessage("failed to store payload link, %v", err).LogReturn()
	}

	// emit event
	timestampString, err := s.emitStorageEvent(ctx, "PAYLOADLINK", key)
	if err != nil {
		// it is safe to forward local errors
		return "", err
	}

	return timestampString, nil
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

	// get caller msp
	invokingMSPID, err := ctx.GetClientIdentity().GetMSPID()
	if err != nil {
		return "", errorcode.Internal.WithMessage("failed to get invoking MSP, %v", err).LogReturn()
	}

	// extract and verify user cert based on PEM
	userCert, err := s.getUserCertFromCertificateChain(ctx, invokingMSPID, signatureObject.Certificate, time.Now())
	if err != nil {
		// it is safe to forward local errors
		return "", err
	}

	// Check if the certificate was used for signing before
	certificateExists, err := s.signatureExistsForCertificate(ctx, userCert, invokingMSPID, storageKey)
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

func (s *RoamingSmartContract) signatureExistsForCertificate(ctx contractapi.TransactionContextInterface, cert *x509.Certificate, mspid, storageKey string) (bool, error) {
	// get all signatures stored for at storage key
	currentSignatures, err := s.GetSignatures(ctx, mspid, storageKey)
	if err != nil {
		// it is safe to forward local errors
		return false, err
	}

	// check if certificate was used for signing already
	for _, storedSignature := range currentSignatures {
		storedCertificateString, err := util.ExtractFieldFromJSON(storedSignature, "certificate")
		if err != nil {
			// it is safe to forward local errors
			return false, err
		}

		storedCertificate, err := certificate.GetLastCertificateFromPEM([]byte(storedCertificateString))
		if err != nil {
			// it is safe to forward local errors
			return false, err
		}

		if storedCertificate.SerialNumber.Cmp(cert.SerialNumber) == 0 {
			return true, nil
		}
	}

	return false, nil
}

// Get the referencePayloadLink
// ACL restricted to local queries only
func (s *RoamingSmartContract) GetReferencePayloadLink(ctx contractapi.TransactionContextInterface, referenceID string) (string, error) {
	log.Debugf("%s(%s)", util.FunctionName(1), referenceID)

	// ACL restricted to local queries only
	if !acl.LocalCall(ctx) {
		return "", errorcode.NonLocalAccessDenied.LogReturn()
	}

	// fetch reference payload link
	referencePayloadLink := util.CalculateHash(referenceID)
	log.Debugf("%s() got reference payload link key %s", util.FunctionName(1), referencePayloadLink)

	// fetch reference payload link value stored by the creator
	referencePayloadLinkValue, err := ctx.GetStub().GetState(referencePayloadLink)
	if err != nil {
		// it is safe to forward local errors
		return "", err
	}

	// check if there is no document
	if referencePayloadLinkValue == nil {
		return "", errorcode.PayloadLinkMissing.WithMessage("no payloadlink found (referenceID %s)", referenceID).LogReturn()
	}

	// done, fetched link
	return string(referencePayloadLinkValue), nil
}

// VerifySignatures checks all stored signature on the ledger against a document
// referenceID  = the referenceID tying everything together
// targetMSPID  = MSP whose signatures to check
// ACL restricted to local queries only
func (s *RoamingSmartContract) VerifySignatures(ctx contractapi.TransactionContextInterface, referenceID, targetMSPID string) (map[string]map[string]string, error) {
	log.Debugf("%s(%s, %s, ...)", util.FunctionName(1), targetMSPID, referenceID)

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
	referencePayloadLink, err := s.GetReferencePayloadLink(ctx, referenceID)
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

		validationError := s.IsValidSignature(ctx, targetMSPID, signaturePayload, signatureObject.Signature, signatureObject.Algorithm, signatureObject.Certificate)
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
	if len(referenceID) != expectedIDLength {
		return "", errorcode.ReferenceIDInvalid.WithMessage("invalid input size of referenceID is invalid as %d != %d", len(referenceID), expectedIDLength).LogReturn()
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
func (s *RoamingSmartContract) fetchBlockchainRef(ctx contractapi.TransactionContextInterface, referenceID string) (*util.BlockchainRef, error) {
	log.Debugf("%s(%s)", util.FunctionName(1), referenceID)

	var result = util.BlockchainRef{}

	// type is fixed hlf for now
	result.Type = `hlf`

	// fetch reference payload link
	referencePayloadLink := util.CalculateHash(referenceID)
	log.Debugf("%s() got reference payload link key %s", util.FunctionName(1), referencePayloadLink)

	// fetch reference payload link value stored by the creator
	iterator, err := ctx.GetStub().GetHistoryForKey(referencePayloadLink)
	if err != nil {
		return nil, errorcode.Internal.WithMessage("failed to get tx history for referenceID %s, %v", referenceID, err).LogReturn()
	}
	defer iterator.Close()

	// There should be exactly one entry in the history
	if !iterator.HasNext() {
		return nil, errorcode.PayloadLinkMissing.WithMessage("no payloadlink found (referenceID %s)", referenceID).LogReturn()
	}

	tx, err := iterator.Next()
	if err != nil {
		return nil, errorcode.Internal.WithMessage("could not retrieve tx from history iterator, %v", err).LogReturn()
	}

	if iterator.HasNext() {
		return nil, errorcode.PayloadLinkMissing.WithMessage("expected 1, got multiple payloadlinks (referenceID %s)", referenceID).LogReturn()
	}

	result.TxID = tx.TxId
	result.Timestamp = time.Unix(tx.GetTimestamp().Seconds, int64(tx.GetTimestamp().Nanos)).Format(time.RFC3339)

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
	referencePayloadLinkValid, err := s.verifyReferencePayloadLink(ctx, referenceID, expectedPayloadHash)
	if err != nil {
		// it is safe to forward local errors
		return "", err
	}

	if !referencePayloadLinkValid {
		return "", errorcode.PayloadLinkInvalid.WithMessage("failed to verify payloadlink on ledger").LogReturn()
	}

	// nice, this document contains the main fields
	// let's add the blockchain reference stuff
	blockchainRef, err := s.fetchBlockchainRef(ctx, referenceID)
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

// SubmitCRL takes a PEM encoded CRL and stores included certificates in the contract's revocation list
func (s *RoamingSmartContract) SubmitCRL(ctx contractapi.TransactionContextInterface, crlPEM string, certChainPEM string) error {
	log.Debugf("%s()", util.FunctionName(1))

	certificateList, err := x509.ParseCRL([]byte(crlPEM))
	if err != nil {
		return errorcode.CRLInvalid.WithMessage("could not parse CRL, %v", err).LogReturn()
	}

	// get caller msp
	invokingMSPID, err := ctx.GetClientIdentity().GetMSPID()
	if err != nil {
		return errorcode.Internal.WithMessage("failed to get invoking MSP, %v", err).LogReturn()
	}

	// get the root certificates for creatorMSP
	rootPEM, err := s.GetCertificate(ctx, invokingMSPID, "root")
	if err != nil {
		return err
	}

	var signingCert *x509.Certificate

	// Check if list is submitted and signed by intermediate CA
	if len(certChainPEM) > 0 {
		// extract and verify user cert based on PEM
		signingCert, err := s.getUserCertFromCertificateChain(ctx, invokingMSPID, certChainPEM, time.Now())
		if err != nil {
			// it is safe to forward local errors
			return err
		}

		// only CAs can revoke certificates
		if !signingCert.IsCA {
			return errorcode.CertInvalid.WithMessage("signing certificate is not a CA cert").LogReturn()
		}

		// verify signature of CRL
		err = signingCert.CheckCRLSignature(certificateList)
		if err != nil {
			return errorcode.SignatureInvalid.WithMessage("CRL signature is invalid, %v", err).LogReturn()
		}
		// Otherwise, the CRL must be signed by a root certificate
	} else {
		certificates, err := certificate.ChainFromPEM([]byte(rootPEM))
		if err != nil {
			return err
		}

		// check if any root certificate matches signature
		for _, certCandidate := range certificates {
			err = certCandidate.CheckCRLSignature(certificateList)
			if err == nil {
				signingCert = certCandidate
				break
			}
		}
		if signingCert == nil {
			return errorcode.SignatureInvalid.WithMessage("No valid root certificate found for CRL signature").LogReturn()
		}
	}

	// append newly revoked certificates to current list and store
	err = storeRevokedCertificates(ctx, invokingMSPID, signingCert, certificateList)

	return err
}

func storeRevokedCertificates(ctx contractapi.TransactionContextInterface, invokingMSPID string, signingCert *x509.Certificate, certificateList *pkix.CertificateList) error {
	// distinguished name of CRL signer
	signerDN := signingCert.Subject.String()

	for _, revokedCertificate := range certificateList.TBSCertList.RevokedCertificates {
		// cunstruct composite key
		// issuer's dn and revoked certificate's serial number are used as identifiers
		storageLocation, err := ctx.GetStub().CreateCompositeKey("msp~configtype~data~dn~serialnumber",
			[]string{invokingMSPID, "certificates", "revoked", signerDN, revokedCertificate.SerialNumber.String()})
		if err != nil {
			return errorcode.Internal.WithMessage("failed to create composite key, %v", err).LogReturn()
		}

		revokedCertificateBytes, err := json.Marshal(revokedCertificate)
		if err != nil {
			return errorcode.Internal.WithMessage("failed to marshal revocation map, %v", err).LogReturn()
		}

		// store updated revocation map
		err = ctx.GetStub().PutState(storageLocation, revokedCertificateBytes)
		if err != nil {
			return errorcode.Internal.WithMessage("failed to store revocation map, %v", err).LogReturn()
		}
	}

	return nil
}
