package util

import (
	"crypto/sha256"
	"encoding/hex"

	couchdb "github.com/leesper/couchdb-golang"
	log "github.com/sirupsen/logrus"
)

const offchainDatabaseName = "offchain_data"

// OffchainDatabasePrepare checks wether the offchain db exists and initializes it if necessary
func OffchainDatabasePrepare(uri string) error {
	log.Debugf("%s()", FunctionName(1))

	// open couchdb connection
	conn, err := couchdb.NewServer(uri)
	if err != nil {
		log.Errorf("failed to access couchdb: %v", err)
		return err
	}

	// check if db exists
	exists := conn.Contains(offchainDatabaseName)
	if exists {
		log.Info("database exists, will do nothing")
		return nil
	}

	log.Info("database does not exist, will initialize it now")
	_, error := conn.Create(offchainDatabaseName)

	return error
}

// OffchainDatabaseStore stores data in the database
func OffchainDatabaseStore(uri string, referenceID string, data OffchainData) (string, error) {
	log.Debugf("%s()", FunctionName(1))

	// open couchdb connection
	conn, err := couchdb.NewServer(uri)
	if err != nil {
		log.Errorf("failed to access couchdb: %v", err)
		return "", err
	}

	// open db
	db, err := conn.Get(offchainDatabaseName)
	if err != nil {
		log.Errorf("failed to open database: %v", err)
		return "", err
	}

	// check if document already exists:
	err = db.Contains(referenceID)
	if err == nil {
		log.Error("failed to store document. referenceID already exists!")
		return "", err
	}

	// attach a couchdb document to the data
	data.Document = couchdb.DocumentWithID(referenceID)

	// store data
	log.Info("will store document now")
	err = couchdb.Store(db, &data)
	if err != nil {
		log.Errorf("failed to store document: %v", err)
		return "", err
	}

	// query document again and calculate hash to make sure the store operation was ok
	log.Info("done. will query document now")
	queryEntry := OffchainData{}
	err = couchdb.Load(db, referenceID, &queryEntry)
	if err != nil {
		log.Errorf("failed to query document: %v", err)
		return "", err
	}

	// calc hash
	sha256 := sha256.Sum256([]byte(queryEntry.Payload))
	payloadHash := hex.EncodeToString(sha256[:])
	log.Info("calculated hash for payload " + queryEntry.GetID() + " as " + payloadHash)

	return payloadHash, nil
}

// OffchainDatabaseFetch fetch data from the database
func OffchainDatabaseFetch(uri string, referenceID string) (OffchainData, error) {
	log.Debugf("%s()", FunctionName(1))

	// prepare data object
	var storedData = OffchainData{}

	// open couchdb connection
	conn, err := couchdb.NewServer(uri)
	if err != nil {
		log.Errorf("failed to access couchdb: %v", err)
		return storedData, err
	}

	// open db
	db, err := conn.Get(offchainDatabaseName)
	if err != nil {
		log.Errorf("failed to open database: %v", err)
		return storedData, err
	}

	// check if document already exists:
	err = db.Contains(referenceID)
	if err != nil {
		log.Error("failed to query document. referenceID '" + referenceID + "' unknown")
		return storedData, err
	}

	// query data
	err = couchdb.Load(db, referenceID, &storedData)
	if err != nil {
		log.Errorf("failed to query document: %v", err)
		return storedData, err
	}

	return storedData, nil
}

// OffchainDatabaseDelete fetch data from the database
func OffchainDatabaseDelete(uri string, referenceID string) error {
	log.Debugf("%s()", FunctionName(1))

	// open couchdb connection
	conn, err := couchdb.NewServer(uri)
	if err != nil {
		log.Errorf("failed to access couchdb: %v", err)
		return err
	}

	// open db
	db, err := conn.Get(offchainDatabaseName)
	if err != nil {
		log.Errorf("failed to open database: %v", err)
		return err
	}

	err = db.Delete(referenceID)
	if err != nil {
		log.Errorf("failed to delete document: %v", err)
		return err
	}

	return nil
}

// OffchainDatabaseFetchAllReferenceIDs fetches all referenceIDs from
// the database and returns an array of referenceIDs.
func OffchainDatabaseFetchAllReferenceIDs(uri string) ([]string, error) {
	log.Debugf("%s()", FunctionName(1))

	// open couchdb connection
	conn, err := couchdb.NewServer(uri)
	if err != nil {
		log.Errorf("failed to access couchdb: %v", err)
		return []string{}, err
	}

	// open db
	db, err := conn.Get(offchainDatabaseName)
	if err != nil {
		log.Errorf("failed to open database: %v", err)
		return []string{}, err
	}

	// fetch all referenceIDs
	ids, err := db.DocIDs()
	if err != nil {
		log.Errorf("failed to query referenceIDs: %v", err)
		return []string{}, err
	}

	return ids, nil
}
