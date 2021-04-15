package certificate

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"hybrid/errorcode"
	"hybrid/util"

	log "github.com/sirupsen/logrus"
)

func ExtractAlgorithmFromUserCert(input []byte) (string, error) {
	log.Debugf("%s(...)", util.FunctionName(1))
	certificate, err := GetLastCertificateFromPEM(input)
	if err != nil {
		return "", err
	}

	// try to extract the algorithm from the last cert in chain
	return certificate.SignatureAlgorithm.String(), nil
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

func GetVerifiedUserCertificate(rootPEM string, certChainPEM string) (*x509.Certificate, error) {
	log.Debugf("%s(..., ...)", util.FunctionName(1))

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

	// make sure the user has the custom attribude "CanSign" = true
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
					canSignValue, canSignExist := attrValue["CanSignDocument"].(string)
					if canSignExist {
						if canSignValue == "yes" {
							CanSignDocument = true
							break
						} else {
							return errorcode.CertInvalid.WithMessage("CanSignDocument attribute value is not yes [%s]", canSignValue).LogReturn()
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
