package baseca

import (
	"sync"
	"time"
)

var Attestation Provider = Provider{
	Local: "Local",
	AWS:   "AWS",
}

var iidCacheExpiration = 10 * time.Minute

type Provider struct {
	Local string
	AWS   string
}

type Authentication struct {
	ClientId    string
	ClientToken string
	AuthToken   string
}

type iidCache struct {
	expiration time.Time
	lock       sync.Mutex
	value      string
}
