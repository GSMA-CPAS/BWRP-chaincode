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
	// DocumentIDExists : this document id already exists
	DocumentIDExists = ErrorCode{"ERROR_DOCUMENT_ID_EXISTS", ""}
	// DocumentIDInvalid :  this document id is invalid
	DocumentIDInvalid = ErrorCode{"ERROR_DOCUMENT_ID_INVALID", ""}
	// DocumentIDUnknown :  this document id is not known
	DocumentIDUnknown = ErrorCode{"ERROR_DOCUMENT_ID_UNKNOWN", ""}
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
	Code    string `json:"code"`
	Message string `json:"message"`
}

// WithMessage adds a custom message to the error:
func (e ErrorCode) WithMessage(format string, vars ...interface{}) ErrorCode {
	e.Message = fmt.Sprintf(format, vars...)
	return e
}

// LogReturn logs and returns a custom error
func (e ErrorCode) LogReturn() error {
	err := errors.New(e.Error())
	log.Error(err)
	return err
}

func (e *ErrorCode) Error() string {
	return e.ToJSON()
}

func (e *ErrorCode) ToJSON() string {
	msg, err := json.Marshal(e)

	if err != nil {
		return BadJSON.WithMessage("failed to marshal error. see chaincode log for details!").LogReturn().Error()
	}

	return string(msg)
}

func FromJSON(e error) (ErrorCode, error) {
	var errorCode ErrorCode
	// try to convert a json string back to an error code
	unmarshallingError := json.Unmarshal([]byte(e.Error()), &errorCode)
	if unmarshallingError != nil {
		return ErrorCode{}, BadJSON.WithMessage("failed to unmarshal error string to ErrorCode object. %v", unmarshallingError).LogReturn()
	}
	return errorCode, nil
}
