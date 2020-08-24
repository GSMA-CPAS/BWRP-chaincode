package mockstub

import (
	"container/list"
	"errors"
	"strings"

	"github.com/hyperledger/fabric-protos-go/ledger/queryresult"
)

/*****************************
 Range Query Iterator
*****************************/

// MockStateRangeQueryIterator ...
type LedgerStateRangeQueryIterator struct {
	Closed   bool
	Ledger   Ledger
	StartKey string
	EndKey   string
	Current  *list.Element
}

//a2
//a1a
//a2a<---S
//a2b
//a3a<---E
//a4a

// HasNext returns true if the range query iterator contains additional keys
// and values.
func (iter *LedgerStateRangeQueryIterator) HasNext() bool {
	if iter.Closed {
		// previously called Close()
		return false
	}

	if iter.Current == nil {
		return false
	}

	current := iter.Current
	for current != nil {
		// if this is an open-ended query for all keys, return true
		if iter.StartKey == "" && iter.EndKey == "" {
			return true
		}
		comp1 := strings.Compare(current.Value.(string), iter.StartKey)
		comp2 := strings.Compare(current.Value.(string), iter.EndKey)
		if comp1 >= 0 {
			if comp2 < 0 {
				return true
			}
			return false
		}
		current = current.Next()
	}
	return false
}

// Next returns the next key and value in the range query iterator.
func (iter *LedgerStateRangeQueryIterator) Next() (*queryresult.KV, error) {
	if iter.Closed == true {
		err := errors.New("LedgerStateRangeQueryIterator.Next() called after Close()")
		return nil, err
	}

	if iter.HasNext() == false {
		err := errors.New("LedgerStateRangeQueryIterator.Next() called when it does not HaveNext()")
		return nil, err
	}

	for iter.Current != nil {
		comp1 := strings.Compare(iter.Current.Value.(string), iter.StartKey)
		comp2 := strings.Compare(iter.Current.Value.(string), iter.EndKey)
		// compare to start and end keys. or, if this is an open-ended query for
		// all keys, it should always return the key and value
		if (comp1 >= 0 && comp2 < 0) || (iter.StartKey == "" && iter.EndKey == "") {
			key := iter.Current.Value.(string)
			value, err := iter.Stub.GetState(key)
			iter.Current = iter.Current.Next()
			return &queryresult.KV{Key: key, Value: value}, err
		}
		iter.Current = iter.Current.Next()
	}
	err := errors.New("LedgerStateRangeQueryIterator.Next() went past end of range")
	return nil, err
}

// Close closes the range query iterator. This should be called when done
// reading from the iterator to free up resources.
func (iter *LedgerStateRangeQueryIterator) Close() error {
	if iter.Closed == true {
		err := errors.New("LedgerStateRangeQueryIterator.Close() called after Close()")
		return err
	}

	iter.Closed = true
	return nil
}

// NewLedgerStateRangeQueryIterator ...
func NewLedgerStateRangeQueryIterator(ledger Ledger, startKey string, endKey string) *LedgerStateRangeQueryIterator {
	iter := new(LedgerStateRangeQueryIterator)
	iter.Closed = false
	iter.ledger = ledger
	iter.StartKey = startKey
	iter.EndKey = endKey
	iter.Current = ledger.database.Keys.Front()
	return iter
}
