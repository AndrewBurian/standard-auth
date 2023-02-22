package jwa

import (
	"errors"

	"go.burian.dev/auth/internal/customencoding"
	"go.burian.dev/auth/jwk"
	"go.burian.dev/auth/jws"
)

type EllipticCurvePublicKey struct {
	jwk.JwkCommonHeader
	Curve string                   `json:"crv"`
	X     customencoding.Base64url `json:"x"`
	Y     customencoding.Base64url `json:"y"`
}

type EllipticCurvePrivateKey struct {
	jwk.JwkCommonHeader
	Curve string                   `json:"crv"`
	X     customencoding.Base64url `json:"x"`
	Y     customencoding.Base64url `json:"y"`
	D     customencoding.Base64url `json:"d"`
}

func (ecpub *EllipticCurvePublicKey) Verify(jws.ValidatedJws) error {
	return errors.New("unimplemented")
}
