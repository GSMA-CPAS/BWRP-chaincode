package mockstub

import (
	"chaincode/offchain_rest/mocks"
	"fmt"
	"unicode/utf8"

	"github.com/hyperledger/fabric-chaincode-go/shim"
	log "github.com/sirupsen/logrus"
)

type ledgerDatabaseEntry []byte

// Ledger contains the main database
type Ledger struct {
	database map[string][]ledgerDatabaseEntry
	stub     *mocks.ChaincodeStub
}

// NewLedger initializes a new Ledger
func NewLedger(s *mocks.ChaincodeStub) *Ledger {
	l := new(Ledger)
	l.database = make(map[string][]ledgerDatabaseEntry)
	l.stub = s
	return l
}

// DumpLedger dumps the full ledger db state
func (ledger Ledger) DumpLedger() {
	for key, val := range ledger.database {
		fmt.Printf("LEDGER[%q] = ", key)
		for _, entry := range val {
			fmt.Printf("[%q], ", string(entry))
		}
		fmt.Printf("\n")
	}
}

// PutState simulates the hlf stub PutState function
func (ledger Ledger) PutState(arg1 string, arg2 []byte) error {
	log.Infof("WRITE ledger[%s] = %s\n", arg1, string(arg2))
	// insert into ledger, append to state
	value, ok := ledger.database[arg1]
	if !ok {
		ledger.database[arg1] = make([]ledgerDatabaseEntry, 0)
	}
	// add data
	ledger.database[arg1] = append(value, arg2)
	ledger.DumpLedger()
	return nil
}

// GetState simulates the hlf stub GetState function:
// GetState returns the value of the specified `key` from the ledger
// If the key does not exist in the state database, (nil, nil) is returned.
//
// TODO: Note that GetState doesn't read data from the writeset, which
// has not been committed to the ledger. In other words, GetState doesn't
// consider data modified by PutState that has not been committed.
func (ledger Ledger) GetState(arg1 string) ([]byte, error) {
	log.Infof("READ ledger[%s] = ", arg1)

	// query ledger
	history, ok := ledger.database[arg1]
	if !ok {
		log.Infof("not found")
		return nil, nil
	}

	// got value, return last element
	return history[len(history)-1], nil
}

// GetStateByPartialCompositeKey queries the state in the ledger based on
// a given partial composite key. This function returns an iterator
// which can be used to iterate over all composite keys whose prefix matches
// the given partial composite key. However, if the number of matching composite
// keys is greater than the totalQueryLimit (defined in core.yaml), this iterator
// cannot be used to fetch all matching keys (results will be limited by the totalQueryLimit).
// The `objectType` and attributes are expected to have only valid utf8 strings and
// should not contain U+0000 (nil byte) and U+10FFFF (biggest and unallocated code point).
// See related functions SplitCompositeKey and CreateCompositeKey.
// Call Close() on the returned StateQueryIteratorInterface object when done.
// The query is re-executed during validation phase to ensure result set
// has not changed since transaction endorsement (phantom reads detected).
func (ledger Ledger) GetStateByPartialCompositeKey(objectType string, attributes []string) (shim.StateQueryIteratorInterface, error) {
	partialCompositeKey, err := ledger.stub.CreateCompositeKey(objectType, attributes)
	if err != nil {
		return nil, err
	}
	fmt.Printf("PARTIAL -%q-\n", partialCompositeKey)
	return NewLedgerStateRangeQueryIterator(partialCompositeKey, partialCompositeKey+string(utf8.MaxRune)), nil
}
