package jwa

import (
	"go.burian.dev/auth/jwk"
)

type HmacKey struct {
	jwk.JwkCommonHeader
	Key []byte `json:"k"`
}

func (hk *HmacKey) Verify() error {

}
