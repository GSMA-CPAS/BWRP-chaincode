// SPDX-FileCopyrightText: 2021 GSMA and all contributors.
// SPDX-License-Identifier: Apache-2.0
package certificate

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"hybrid/errorcode"
	"hybrid/util"
	"time"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
	log "github.com/sirupsen/logrus"

	cert_util "k8s.io/client-go/util/cert"
)

func ExtractAlgorithmFromUserCert(input []byte) (*x509.SignatureAlgorithm, error) {
	log.Debugf("%s(...)", util.FunctionName(1))

	certificate, err := GetLastCertificateFromPEM(input)
	if err != nil {
		return nil, err
	}

	// try to extract the algorithm from the last cert in chain
	return &certificate.SignatureAlgorithm, nil
}

func GetLastCertificateFromPEM(input []byte) (*x509.Certificate, error) {
	chain, err := ChainFromPEM(input)
	if err != nil {
		return nil, err
	}

	return chain[len(chain)-1], nil
}

func ChainFromPEM(input []byte) ([]*x509.Certificate, error) {
	log.Debugf("%s(...)", util.FunctionName(1))

	var certificates []*x509.Certificate

	for {
		block, rest := pem.Decode(input)
		if block == nil {
			break
		}
		// try to extract the cert
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, errorcode.CertInvalid.WithMessage("failed to parse certificate, %v", err).LogReturn()
		}

		//log.Debugf("parsed certificate")

		// add to list
		certificates = append(certificates, cert)

		// continue with the rest of the chain
		input = rest
	}
	log.Debugf("parsed %d intermediate and user certs", len(certificates))

	return certificates, nil
}

func GetVerifiedUserCertificate(ctx contractapi.TransactionContextInterface, msp string, rootPEM string, certChainPEM string, atTime time.Time) (*x509.Certificate, error) {
	log.Debugf("%s(..., ...)", util.FunctionName(1))

	// check if any certificate was revoked
	certRevoked, err := AnyCertificateRevokedFromPEM(ctx, msp, atTime, []byte(certChainPEM))
	if err != nil {
		return nil, err
	}
	if certRevoked {
		return nil, errorcode.CertInvalid.WithMessage("Certificate in the cert chain has been revoked").LogReturn()
	}

	// read PEM and create a certificate list
	intermediateCerts, userCert, err := IntermediateAndUserFromPEM([]byte(certChainPEM))
	if err != nil {
		// it is safe to forward local errors
		return nil, err
	}

	// make sure the intermediate certs all habe CA flag set:
	err = CheckIntermediates(intermediateCerts)
	if err != nil {
		// it is safe to forward local errors
		return nil, err
	}

	// make sure user Cert is valid and has all flags:
	err = CheckUser(userCert)
	if err != nil {
		// it is safe to forward local errors
		return nil, err
	}

	// add certs from PEM to certPool
	rootCertPool := x509.NewCertPool()
	if !rootCertPool.AppendCertsFromPEM([]byte(rootPEM)) {
		return nil, errorcode.CertInvalid.WithMessage("failed to build certPool from root PEM\n %s", rootPEM).LogReturn()
	}
	//log.Debugf("loaded root cert " + rootPEM)

	// add intermediate certs to pool
	interCertPool := x509.NewCertPool()

	for _, cert := range intermediateCerts {
		interCertPool.AddCert(cert)
	}

	// create verification options
	opts := x509.VerifyOptions{
		Roots:         rootCertPool,
		Intermediates: interCertPool,
	}

	// make sure we can build a trusted chain from root to user
	_, err = userCert.Verify(opts)
	if err != nil {
		return nil, errorcode.CertInvalid.WithMessage("failed to verify user certificate, %v", err).LogReturn()
	}

	return userCert, nil
}

func IntermediateAndUserFromPEM(input []byte) ([]*x509.Certificate, *x509.Certificate, error) {
	log.Debugf("%s(...)", util.FunctionName(1))
	// extract all certs from PEM
	certificates, err := ChainFromPEM(input)
	if err != nil {
		return nil, nil, err
	}

	// extract the user cert
	userCert := certificates[len(certificates)-1]

	// extract intermediates
	intermediateCerts := certificates[:len(certificates)-1]
	log.Debugf("got %d intermediate certs", len(intermediateCerts))

	return intermediateCerts, userCert, nil
}

func CheckIntermediates(intermediateCerts []*x509.Certificate) error {
	log.Debugf("%s(...)", util.FunctionName(1))
	// make sure the intermediate certs all habe CA flag set:
	for i, cert := range intermediateCerts {
		if !cert.IsCA {
			return errorcode.CertInvalid.WithMessage("intermediate cert %d is not a CA cert", i).LogReturn()
		}
	}

	log.Debugf("checked %d intermediate certs: ok", len(intermediateCerts))

	// all fine
	return nil
}

func CheckUser(userCert *x509.Certificate) error {
	log.Debugf("%s(...)", util.FunctionName(1))
	// make sure the user cert does NOT have the CA flag set
	if userCert.IsCA {
		return errorcode.CertInvalid.WithMessage("user cert is not allowed to be a CA cert").LogReturn()
	}

	// make sure the user has the custom attribude "CanSignDocument" = true
	var CanSignDocument = false

	var oidCustomAttribute = asn1.ObjectIdentifier{1, 2, 3, 4, 5, 6, 7, 8, 1}

	for _, ext := range userCert.Extensions {
		if ext.Id.Equal(oidCustomAttribute) {
			var result map[string]interface{}
			err := json.Unmarshal(ext.Value, &result)

			if err != nil {
				// do not abort here, this might just be some
				// different, non-json attribute that we do not care about
				log.Debugf("ignoring non json data in custom extension field: %v", err)
			} else {
				// try to extract
				attrValue, exist := result["attrs"].(map[string]interface{})
				if exist {
					canSignDocumentValue, canSignDocumentExist := attrValue["CanSignDocument"].(string)
					if canSignDocumentExist {
						if canSignDocumentValue == "yes" {
							CanSignDocument = true
							break
						} else {
							return errorcode.CertInvalid.WithMessage("CanSignDocument attribute value is not yes [%s]", canSignDocumentValue).LogReturn()
						}
					}
				}
			}
		}
	}

	// check flag
	if !CanSignDocument {
		return errorcode.CertInvalid.WithMessage("CanSignDocument not set").LogReturn()
	}

	// all fine
	return nil
}

func AnyCertificateRevokedFromPEM(ctx contractapi.TransactionContextInterface, msp string, atTime time.Time, pems ...[]byte) (bool, error) {
	var certificates []*x509.Certificate

	// get certificates from PEM
	for _, pem := range pems {
		certChain, err := ChainFromPEM(pem)
		if err != nil {
			return true, err
		}
		certificates = append(certificates, certChain...)
	}

	return AnyCertificateRevoked(ctx, msp, atTime, certificates...)
}

func AnyCertificateRevoked(ctx contractapi.TransactionContextInterface, msp string, atTime time.Time, certificates ...*x509.Certificate) (bool, error) {
	log.Debugf("%s(...)", util.FunctionName(1))

	// remove all certificates that have been revoked from array
	filteredCertificates, err := removeRevokedCertificates(ctx, msp, certificates, atTime)
	if err != nil {
		return true, err
	}

	// check if any certificates have been removed
	if len(filteredCertificates) != len(certificates) {
		return true, nil
	}

	return false, nil
}

func FilterRevokedRootCertificates(ctx contractapi.TransactionContextInterface, msp string, certsPEM []byte, atTime time.Time) ([]byte, error) {
	log.Debugf("%s(...)", util.FunctionName(1))

	// retrieve certificates from PEM
	certificates, err := ChainFromPEM(certsPEM)
	if err != nil {
		return nil, err
	}

	// remove all certificates that have been revoked from array
	certificates, err = removeRevokedCertificates(ctx, msp, certificates, atTime)
	if err != nil {
		return nil, err
	}

	// encode back to PEM
	filteredPEM, err := cert_util.EncodeCertificates(certificates...)
	if err != nil {
		return nil, errorcode.Internal.WithMessage("could not encode certificates to PEM, %s", err).LogReturn()
	}

	return filteredPEM, nil
}

func removeRevokedCertificates(ctx contractapi.TransactionContextInterface, msp string, certificates []*x509.Certificate, atTime time.Time) ([]*x509.Certificate, error) {
	// Check if certificate was revoked for each certificate of array
	// We iterate from the back so the index doesn't become messed up when removing revoked items from the certificates array
	for i := len(certificates) - 1; i >= 0; i-- {
		// distinguised name of issuing CA
		issuerDN := certificates[i].Issuer.String()
		// serial number of certificate
		certSN := certificates[i].SerialNumber.String()

		// build composite key for issuer and certificate
		compositeKey, err := ctx.GetStub().CreateCompositeKey("msp~configtype~data~dn~serialnumber", []string{msp, "certificates", "revoked", issuerDN, certSN})
		if err != nil {
			return nil, errorcode.Internal.WithMessage("failed to create composite key, %v", err).LogReturn()
		}

		// retrieve potenitally revoked certificate
		revokedCertBytes, err := ctx.GetStub().GetState(compositeKey)
		if err != nil {
			return nil, errorcode.Internal.WithMessage("failed to query revoked cert, %v", err).LogReturn()
		}

		// Check if a revoked certificate was retrieved
		if len(revokedCertBytes) > 0 {
			var revokedCert pkix.RevokedCertificate
			_, err = asn1.Unmarshal(revokedCertBytes, &revokedCert)
			if err != nil {
				return nil, errorcode.Internal.WithMessage("failed to unmarshal revoked certificate, %v", err).LogReturn()
			}

			// Check if the revocation happened before the target time
			if revokedCert.RevocationTime.Before(atTime) {
				// remove certificate from array
				certificates = append(certificates[:i], certificates[i+1:]...)
			} else if len(revokedCert.Extensions) > 0 {
				// An earlier invalidity date may have been specified in extension
				for _, extension := range revokedCert.Extensions {
					// Check if extension is Invalidity Date (rfc5280: 5.3.2), OID: id-ce 24
					if extension.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 24}) {
						var timestamp time.Time
						_, err := asn1.Unmarshal(extension.Value, &timestamp)
						if err != nil {
							return nil, errorcode.Internal.WithMessage("could not unmarshal time value: %s", err).LogReturn()
						}
						// timestamp, err := time.Parse("20060102150405Z", string(extension.Value))
						// if err != nil {
						// 	return nil, errorcode.Internal.WithMessage("could not parse invalidity date of revoked certificate: %s", err).LogReturn()
						// }
						if timestamp.Before(atTime) {
							// remove certificate from array
							certificates = append(certificates[:i], certificates[i+1:]...)
						}
					}
				}
			}
		}
	}

	return certificates, nil
}
