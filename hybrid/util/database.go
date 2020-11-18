package util

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	couchdb "github.com/leesper/couchdb-golang"
	log "github.com/sirupsen/logrus"
)

const offchainDatabaseName = "offchain_data"

// OffchainDatabasePrepare checks wether the offchain db exists and initializes it if necessary
func OffchainDatabasePrepare(uri string) error {
	log.Debugf("%s()", FunctionName())

	// open couchdb connection
	conn, err := couchdb.NewServer(uri)
	if err != nil {
		log.Error("failed to access couchdb: " + err.Error())
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
func OffchainDatabaseStore(uri string, documentID string, data OffchainData) (string, error) {
	log.Debugf("%s()", FunctionName())

	// open couchdb connection
	conn, err := couchdb.NewServer(uri)
	if err != nil {
		log.Error("failed to access couchdb: " + err.Error())
		return "", err
	}

	// open db
	db, err := conn.Get(offchainDatabaseName)
	if err != nil {
		log.Error("failed to open database: " + err.Error())
		return "", err
	}

	// check if document already exists:
	err = db.Contains(documentID)
	if err == nil {
		log.Error("failed to store document. documentID already exists!")
		return "", fmt.Errorf("failed to store document. documentID %s exists", documentID)
	}

	// attach a couchdb document to the data
	data.Document = couchdb.DocumentWithID(documentID)

	// store data
	log.Info("will store document now")
	err = couchdb.Store(db, &data)
	if err != nil {
		log.Error("failed to store document: " + err.Error())
		return "", err
	}

	// query document again and calculate hash to make sure the store operation was ok
	log.Info("done. will query document now")
	queryEntry := OffchainData{}
	err = couchdb.Load(db, documentID, &queryEntry)
	if err != nil {
		log.Error("failed to query document: " + err.Error())
		return "", err
	}

	// calc hash
	sha256 := sha256.Sum256([]byte(queryEntry.Data))
	dataHash := hex.EncodeToString(sha256[:])
	log.Info("calculated hash for document " + queryEntry.GetID() + " as " + dataHash)

	return dataHash, nil
}

// OffchainDatabaseFetch fetch data from the database
func OffchainDatabaseFetch(uri string, documentID string) (OffchainData, error) {
	log.Debugf("%s()", FunctionName())

	// prepare data object
	var storedData = OffchainData{}

	// open couchdb connection
	conn, err := couchdb.NewServer(uri)
	if err != nil {
		log.Error("failed to access couchdb: " + err.Error())
		return storedData, err
	}

	// open db
	db, err := conn.Get(offchainDatabaseName)
	if err != nil {
		log.Error("failed to open database: " + err.Error())
		return storedData, err
	}

	// check if document already exists:
	err = db.Contains(documentID)
	if err != nil {
		log.Error("failed to query document. documentID '" + documentID + "' unknown")
		return storedData, fmt.Errorf("failed to query document. documentID '"+documentID+"' unknown %s", err.Error())
	}

	// query data
	err = couchdb.Load(db, documentID, &storedData)
	if err != nil {
		log.Error("failed to query document: " + err.Error())
		return storedData, err
	}

	return storedData, nil
}

// OffchainDatabaseDelete fetch data from the database
func OffchainDatabaseDelete(uri string, documentID string) error {
	log.Debugf("%s()", FunctionName())

	// open couchdb connection
	conn, err := couchdb.NewServer(uri)
	if err != nil {
		log.Error("failed to access couchdb: " + err.Error())
		return err
	}

	// open db
	db, err := conn.Get(offchainDatabaseName)
	if err != nil {
		log.Error("failed to open database: " + err.Error())
		return err
	}

	err = db.Delete(documentID)
	if err != nil {
		log.Error("failed to delete document: " + err.Error())
		return err
	}

	return nil
}

// OffchainDatabaseFetchAllDocumentIDs fetches all document ids from
// the database and returns an array of IDs.
func OffchainDatabaseFetchAllDocumentIDs(uri string) ([]string, error) {
	log.Debugf("%s()", FunctionName())

	// open couchdb connection
	conn, err := couchdb.NewServer(uri)
	if err != nil {
		log.Error("failed to access couchdb: " + err.Error())
		return []string{}, err
	}

	// open db
	db, err := conn.Get(offchainDatabaseName)
	if err != nil {
		log.Error("failed to open database: " + err.Error())
		return []string{}, err
	}

	// fetch all document ids
	ids, err := db.DocIDs()
	if err != nil {
		log.Error("failed to query document IDs: " + err.Error())
		return []string{}, err
	}

	return ids, nil
}
