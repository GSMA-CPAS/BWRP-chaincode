package util
import "github.com/leesper/couchdb-golang"

// prepareOffchainDatabase checks wether the offchain db exists and initializes it if necessary
func prepareOffchainDatabase(string uri) error {
	exists, err := checkOffchainDatabaseExists()
	if err != nil {
		log.Infof("error: failed to access couchdb: " + err)
		return err;
	}
	if exists {
		log.Infof("database exists, will do nothing")
		return nil;
	}

	log.Infof("database does not exist, will initialize it now")
	return initOffchainDatabase(uri);
}

// checkOffchainDatabaseExists checks wether the offchain db exists
func checkOffchainDatabaseExists(string uri) bool, error {
}

// initOffchainDatabase initializes a db
func initOffchainDatabase(string uri) error {
	
}




