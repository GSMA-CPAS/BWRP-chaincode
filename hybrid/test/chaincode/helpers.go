// SPDX-FileCopyrightText: 2021 GSMA and all contributors.
// SPDX-License-Identifier: Apache-2.0
package chaincode

import (
	"bytes"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"hybrid/certificate"
	"hybrid/errorcode"
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
	result.Algorithm, err = certificate.GetStringFromSignatureAlgorithm(*algorithm)
	if err != nil {
		return result, err
	}

	// create signature
	pblock, _ := pem.Decode([]byte(privateKey))
	pkey, err := x509.ParsePKCS8PrivateKey(pblock.Bytes)
	if err != nil {
		return result, err
	}

	// The document is hashed and signed using the same algorithm as used for certificate
	hashAlgorithm, err := certificate.GetHashAlgorithmFromSignatureAlgortithm(*algorithm)
	if err != nil {
		return result, err
	}

	hashInstance := hashAlgorithm.New()
	hashInstance.Write([]byte(payload))
	hash := hashInstance.Sum(nil)

	pubKeyAlgorithm, err := certificate.GetPubKeyAlgorithmFromSignatureAlgortithm(*algorithm)
	if err != nil {
		return result, err
	}

	var signature []byte

	// sign hash of payload according to public key algorithm used in certificate
	switch *pubKeyAlgorithm {
	case x509.ECDSA:
		signature, err = ecdsa.SignASN1(rand.Reader, pkey.(*ecdsa.PrivateKey), hash[:])
	case x509.RSA:
		signature, err = rsa.SignPKCS1v15(rand.Reader, pkey.(*rsa.PrivateKey), *hashAlgorithm, hash[:])
	case x509.DSA:
		var s util.DsaSignature
		s.S, s.R, err = dsa.Sign(rand.Reader, pkey.(*dsa.PrivateKey), hash[:])
		if err != nil {
			return result, nil
		}
		signature, err = asn1.Marshal(s)
	default:
		return result, errorcode.SignatureInvalid.WithMessage("signature algorithm not supported").LogReturn()
	}
	if err != nil {
		return result, err
	}

	// store signature
	result.Signature = base64.StdEncoding.EncodeToString(signature)

	//log.Infof("> sign payload '%s' = %s", payload, result.Signature)

	return result, err
}
