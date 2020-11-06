package couchdb_dummy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	log "github.com/sirupsen/logrus"
)

// dummy database:
// dummydb[hostname][id] = data
var dummyDB = map[string]map[string]string{}

func storeData(c echo.Context) error {
	body, _ := ioutil.ReadAll(c.Request().Body)
	log.Infof("on %s got: %s", c.Echo().Server.Addr, string(body))

	// extract hash
	id := c.Param("id")
	if len(id) != 64 {
		return c.String(http.StatusInternalServerError, `{ "error": "invalid id parameter. length mismatch `+string(len(id))+`" }`)
	}

	_, knownHash := dummyDB[c.Echo().Server.Addr]
	if !knownHash {
		log.Infof("could not find host " + c.Echo().Server.Addr + " in db")
		os.Exit(0)
	}

	//store data
	log.Infof("DB[%s][%s] = %s", c.Echo().Server.Addr, id, string(body))
	dummyDB[c.Echo().Server.Addr][id] = string(body)

	// calc hash for return value
	var document map[string]interface{}
	err := json.Unmarshal(body, &document)
	if err != nil {
		log.Error("failed to unmarshal JSON " + err.Error())
		return err
	}

	data := document["data"].(string)
	hash := sha256.Sum256([]byte(data))
	hashs := hex.EncodeToString(hash[:])
	log.Infof("done, hash is " + hashs)

	// return the hash in the same way as the offchain-db-adapter
	return c.String(http.StatusOK, `{"ok":true,"id":"`+id+`","rev":"1-ba8d8812afd2ba7be6c81c2e4c90e9c4"}`)
}

func fetchDocument(c echo.Context) error {
	// extract id
	id := c.Param("id")
	if len(id) != 64 {
		return c.String(http.StatusInternalServerError, `{ "error": "invalid id parameter. length mismatch `+string(len(id))+`" }`)
	}

	// access dummy db
	log.Infof("accessing dummyDB[%s][%s]", c.Echo().Server.Addr, id)
	val, knownHash := dummyDB[c.Echo().Server.Addr][id]
	if !knownHash {
		log.Infof("could not find id " + id + " in db")
		return c.String(http.StatusNotFound, `{"error":"not_found","reason":"missing"}`)
	}

	// return the data
	log.Infof("ok, returning dummyDB[%s] = %s", id, val)
	return c.String(http.StatusOK, val)
}

func fetchDocuments(c echo.Context) error {
	var documents map[string]map[string]interface{}
	documents = make(map[string]map[string]interface{})

	for id, data := range dummyDB[c.Echo().Server.Addr] {
		var document map[string]interface{}
		json.Unmarshal([]byte(data), &document)

		documents[id] = document
	}

	val, err := json.Marshal(documents)

	if err != nil {
		return c.String(http.StatusInternalServerError, err.Error())
	}

	// return the data
	return c.String(http.StatusOK, string(val))
}

func fetchDocumentID(c echo.Context) error {
	// extract id
	storageKey := c.Param("storageKey")
	if len(storageKey) != 64 {
		return c.String(http.StatusInternalServerError, `{ "error": "invalid id parameter. length mismatch `+string(len(storageKey))+`" }`)
	}

	// access dummy db
	// loop through all (inefficient but good enough for this test)
	for id, data := range dummyDB[c.Echo().Server.Addr] {
		var document map[string]interface{}
		json.Unmarshal([]byte(data), &document)

		// calc hash of from storageKey
		tmp := sha256.Sum256([]byte(document["fromMSP"].(string) + id))
		if hex.EncodeToString(tmp[:]) == storageKey {
			return c.String(http.StatusOK, `{ "documentID": "`+id+`" }`)
		}
		// calc hash of to storageKey
		tmp = sha256.Sum256([]byte(document["fromMSP"].(string) + id))
		if hex.EncodeToString(tmp[:]) == storageKey {
			return c.String(http.StatusOK, `{ "documentID": "`+id+`" }`)
		}
	}

	log.Errorf("could not find storageKey " + storageKey + " in db")
	return c.String(http.StatusInternalServerError, "id not found")
}

func fetchAllDocumentIDs(c echo.Context) error {
	// access dummy db
	db := dummyDB[c.Echo().Server.Addr]

	// {1, 2, 3}

	// CONTINUE: required response:
	// curl -X GET -v 'http://user:pw@localhost:5984/offchain_data/_all_docs'
	//
	//{"total_rows":1,"offset":0,"rows":[
	//{"id":"324aa9cf10e4bb8bd8995d2cb76dbbf6afe097ad06c766e68ea14d55452e9e8a","key":"324aa9cf10e4bb8bd8995d2cb76dbbf6afe097ad06c766e68ea14d55452e9e8a","value":{"rev":"1-ba8d8812afd2ba7be6c81c2e4c90e9c4"}}
	//]}

	res, err := json.Marshal(db)
	if err != nil {
		log.Info(err.Error())
		return c.String(http.StatusInternalServerError, `{"error" = "`+err.Error()+`"}`)
	}

	return c.String(http.StatusOK, string(res))
}

func returnOK(c echo.Context) error {
	return c.String(http.StatusOK, `{ "ok": true }`)
}

// StartServer will start a dummy rest server
func StartServer(port int) {
	e := echo.New()
	// enable this to see all requests
	e.Debug = true
	e.Use(middleware.Logger())

	// define routes
	//e.PUT("/documents/:id", storeData)
	//e.GET("/documents/:id", fetchDocument)
	//e.GET("/documents", fetchDocuments)
	//e.GET("/documentIDs/:storageKey", fetchDocumentID)

	e.GET("/offchain_data", returnOK)
	e.HEAD("/offchain_data", returnOK)
	e.HEAD("/offchain_data/:id", fetchDocument)
	e.PUT("/offchain_data/:id", storeData)
	e.GET("/offchain_data/:id", fetchDocument)
	e.GET("/offchain_data/_all_docs", fetchAllDocumentIDs)

	// start server
	url := ":" + strconv.Itoa(port)
	log.Info("will listen on " + url)

	// add dummydb
	dummyDB[url] = make(map[string]string)

	go func() {
		err := e.Start(url)
		if err != nil {
			log.Panic(err)
		}
	}()
	time.Sleep(200 * time.Millisecond)
}
