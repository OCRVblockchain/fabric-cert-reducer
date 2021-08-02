package store

import (
	"crypto/sha256"
	"sync"
	"time"
)

const dbFile = ".cert_cache"

type storage struct {
	sync.RWMutex
	db    *leveldb.DB
	cache *cache.Cache
}

var store = func() *storage {
	db, err := leveldb.OpenFile(dbFile, nil)
	if err != nil {
		logger.Fatal(err)
	}
	return &storage{db: db, cache: cache.New(5*time.Minute, 10*time.Minute)}
}()

func Save(cert []byte) []byte {
	store.Lock()
	defer store.Unlock()
	id := makeID(cert)
	if err := store.db.Put(id, cert, nil); err != nil {
		logger.Warn(err)
	}
	store.cache.Add(string(id), cert, cache.DefaultExpiration)

	return id
}

func Get(id []byte) []byte {
	store.RLock()
	defer store.RUnlock()

	if cert, exists := store.cache.Get(string(id)); exists {
		return cert.([]byte)
	}

	return store.db.Get(id, nil)
}

func makeID(cert []byte) []byte {
	id := sha256.Sum256(cert)
	return id[:]
}
