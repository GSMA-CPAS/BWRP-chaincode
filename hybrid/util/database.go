package util

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	couchdb "github.com/leesper/couchdb-golang"
	log "github.com/sirupsen/logrus"
)

const offchainDatabaseName = "offchain_data"

/*type OffchainData struct {
	Data string
	couchdb.Document
}
*/

// OffchainDatabasePrepare checks wether the offchain db exists and initializes it if necessary
func OffchainDatabasePrepare(uri string) error {
	// set loglevel
	log.SetLevel(log.InfoLevel)

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
	// set loglevel
	log.SetLevel(log.InfoLevel)

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
func OffchainDatabaseFetch(uri string, documentID string) ([]byte, error) {
	// set loglevel
	log.SetLevel(log.InfoLevel)

	// open couchdb connection
	conn, err := couchdb.NewServer(uri)
	if err != nil {
		log.Error("failed to access couchdb: " + err.Error())
		return nil, err
	}

	// open db
	db, err := conn.Get(offchainDatabaseName)
	if err != nil {
		log.Error("failed to open database: " + err.Error())
		return nil, err
	}

	// check if document already exists:
	err = db.Contains(documentID)
	if err != nil {
		log.Error("failed to query document. documentID unknown")
		return nil, fmt.Errorf("failed to query document. documentID unknown %s", err.Error())
	}

	// query data
	storedData, err := db.GetAttachmentID(documentID, "data")
	if err != nil {
		log.Error("failed to query document: " + err.Error())
		return nil, err
	}

	return storedData, nil
}
