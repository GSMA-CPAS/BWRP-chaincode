package errorcode

import (
	"encoding/json"
	"errors"
	"fmt"

	log "github.com/sirupsen/logrus"
)

var (
	// NonLocalAccessDenied : the ACL prevents a non local execution
	NonLocalAccessDenied = ErrorCode{"ERROR_NON_LOCAL_ACCESS_DENIED", ""}
	// OffchainDBConfig : the offchaindb config is missing / unconfigured or there was an error retrieving it
	OffchainDBConfig = ErrorCode{"ERROR_OFFCHAIN_DB_CONFIG", ""}
	// Internal : something inside hyperledger is broken
	Internal = ErrorCode{"ERROR_INTERNAL", ""}
	// ReferenceIDExists : this referenceID already exists
	ReferenceIDExists = ErrorCode{"ERROR_REFERENCE_ID_EXISTS", ""}
	// ReferenceIDInvalid :  this referenceID is invalid
	ReferenceIDInvalid = ErrorCode{"ERROR_REFERENCE_ID_INVALID", ""}
	// ReferenceIDUnknown :  this referenceID is not known
	ReferenceIDUnknown = ErrorCode{"ERROR_REFERENCE_ID_UNKNOWN", ""}
	// TargetMSPInvalid : this MSP id is invalid
	TargetMSPInvalid = ErrorCode{"ERROR_TARGET_MSP_INVALID", ""}
	// CertInvalid : the supplied certificate is invalid
	CertInvalid = ErrorCode{"ERROR_CERT_INVALID", ""}
	// SignatureInvalid : the supplied signature is invalid
	SignatureInvalid = ErrorCode{"ERROR_SIGNATURE_INVALID", ""}
	// BadJSON : something went wrong when parsing a json string
	BadJSON = ErrorCode{"ERROR_BAD_JSON", ""}
)

// ErrorCode is our custom error
type ErrorCode struct {
	code    string
	message string
}

// WithMessage adds a custom message to the error:
func (e ErrorCode) WithMessage(format string, vars ...interface{}) ErrorCode {
	e.message = fmt.Sprintf(format, vars...)
	return e
}

// LogReturn logs and returns a custom error
func (e ErrorCode) LogReturn() error {
	err := errors.New(e.Error())
	log.Error(err)
	return err
}

func jsonEscape(i string) (string, error) {
	b, err := json.Marshal(i)
	if err != nil {
		return "", err
	}
	// Trim the beginning and trailing " character
	return string(b[1 : len(b)-1]), nil
}

func (e *ErrorCode) Error() string {
	msg, err := jsonEscape(e.message)

	if err != nil {
		log.Errorf("failed to escape to json, %v", err)
		msg = "ERROR: could not escape json, see chaincode log for details!"
	}

	return fmt.Sprintf(`{ "code": "%s", "message": "%s" }`, e.code, msg)
}
