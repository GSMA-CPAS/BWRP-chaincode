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
	// Payloadlink : no payload link found
	PayloadLinkMissing = ErrorCode{"ERROR_PAYLOADLINK_MISSING", ""}
	// Payloadlink : mismatch
	PayloadLinkInvalid = ErrorCode{"ERROR_PAYLOADLINK_INVALID", ""}
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
	// CertAlreadyExists : certificate was used for signing already
	CertAlreadyExists = ErrorCode{"ERROR_CERT_ALREADY_EXISTS", ""}
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

func (e *ErrorCode) Matches(err error) bool {
	// try to parse error as custom error:
	customErr, err := FromJSON(err)
	if err != nil {
		log.Error(err)
		return false
	}

	return customErr.Code == e.Code
}
