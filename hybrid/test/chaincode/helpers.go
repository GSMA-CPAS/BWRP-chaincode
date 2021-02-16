package chaincode

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"hybrid/certificate"
	"hybrid/test/historyshimtest"
	"hybrid/test/mocks"
	"hybrid/util"

	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric-chaincode-go/pkg/cid"
	"github.com/hyperledger/fabric-protos-go/msp"
	log "github.com/sirupsen/logrus"
)

// PrepareTransactionContext prepares a tx context
func PrepareTransactionContext(stub *historyshimtest.MockStub, orgmsp string, cert string) (*mocks.TransactionContext, error) {
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
		log.Infof("txID: %s => signature: <%s>", txID, signature)
	}
}

// CheckSignatureResponse prints a formatted response and checks the results
func CheckSignatureResponse(input map[string]map[string]string) error {
	res, _ := json.Marshal(input)
	// nice formatting:
	var out bytes.Buffer
	_ = json.Indent(&out, res, "", "  ")

	// log it
	log.Info("\n" + out.String())

	// check all verification results
	for key, element := range input {
		if element["valid"] != "true" {
			log.Errorf("found invalid signature for tx %s, code: %s, reason: %s", key, element["errorcode"], element["message"])
			return fmt.Errorf("failed to verify tx %s, code: %s, reason: %s", key, element["errorcode"], element["message"])
		}
	}

	return nil
}

func createIdentity(mspID string, cert string) ([]byte, error) {
	sid := &msp.SerializedIdentity{Mspid: mspID, IdBytes: []byte(cert)}
	b, err := proto.Marshal(sid)
	return b, err
}

func CreateSignaturePayload(mspID string, referenceID string, referencePayloadLink string) string {
	return util.CalculateHash(util.HashConcat(mspID, referenceID, referencePayloadLink))
}

func SignPayload(payload string, privateKey string, certChain string) (util.Signature, error) {
	var result util.Signature

	// store chain
	result.Certificate = certChain

	// decode algorithm used from cert
	algorithm, err := certificate.ExtractAlgorithmFromUserCert([]byte(certChain))
	if err != nil {
		return result, err
	}
	result.Algorithm = algorithm

	// create signature
	pblock, _ := pem.Decode([]byte(privateKey))
	pkey, err := x509.ParsePKCS8PrivateKey(pblock.Bytes)
	if err != nil {
		return result, err
	}

	// FIXME: use the proper hash as specified in result.Algorithm!
	// calc hash of document
	hash := sha256.Sum256([]byte(payload))

	// sign hash of payload
	signature, err := ecdsa.SignASN1(rand.Reader, pkey.(*ecdsa.PrivateKey), hash[:])

	// store signature
	result.Signature = base64.StdEncoding.EncodeToString(signature)

	//log.Infof("> sign payload '%s' = %s", payload, result.Signature)

	return result, err
}
