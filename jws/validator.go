package jws

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// General JWS Errors
var (
	ErrNoAlgHeader          = errors.New("no alg header present in JWS")
	ErrUnknownCritExtension = errors.New("cannot continue with unknown critical extension")
)

// Errors for the NoneValidator
var (
	ErrAuthNotNone          = errors.New("attempt to none authenticate JWS with signing header")
	ErrAuthSignaturePresent = errors.New("attempt to none authenticate JWS where signature was not empty bytes")
)

// Errors for JWKValidator
var (
	ErrNoKeyResolution = errors.New("unable to locate appropriate JWK for authenitcation")
	ErrJkuUnprotected  = errors.New("jku URL does not implement https")
)

type Validator interface {
	Validate(UnverifiedJws) (ValidatedJws, error)
}

// iterates through an unverified JWS, generating possible valid
// signatures sets. If the provided function returns no error, the function returns
// that JWS as valid. If no combination works, it returns an error
func validateEachSignature(unsafeJws UnverifiedJws, validatorFunc func(*validJws) error) (*validJws, error) {

	var err error

	// iterate through all the signatures looking for one we can validate
	for _, sig := range unsafeJws.GetSignatures() {

		jws := &validJws{
			Protected:   sig.protectedRaw,
			Unprotected: sig.Header,
			Payload:     unsafeJws.GetPayload(),
		}

		jws.Signature = make([]byte, base64url.DecodedLen(len(sig.Signature)))
		base64url.Decode(jws.Signature, []byte(sig.Signature))

		err = validatorFunc(jws)
		if err == nil {
			return jws, nil
		}
	}

	// if there's only one signature, may as well report the error with it
	if len(unsafeJws.GetSignatures()) == 1 {
		return nil, fmt.Errorf("error in signature: %w", err)
	}

	// otherwise generic error
	return nil, errors.New("no signature found to be acceptable")

}

// NoneValidator reads JWS tokens with `{"alg": "none"}` headers.
//
// These JWS objects provide no authentication and should be used only for testing.
// To prevent accidental misuse, attempting to authenticate a JWS that declares an alg header
// other than none produces an ErrAuthNotNone error, but also returns a JWS as well.
type NoneValidator struct{}

func (*NoneValidator) Validate(unsafeJws UnverifiedJws) (ValidatedJws, error) {

	return validateEachSignature(unsafeJws, func(jws *validJws) error {

		// RFC 7515 § 4.1.11: Receiver MUST validate extensions listed in crit.
		// this authenticator doesn't support any extensions
		// if any are listed, we must fail
		if jws.UnprotectedHeader().Critical() != nil {
			return fmt.Errorf("unknown JWS extention: %w", ErrUnknownCritExtension)
		}

		// RFC 7515 § 4.1.1: A JWS MUST contain an "alg" header.
		// The none authenticator refuses to run on JWS with any actual signature alg
		// set to prevent it accidentally "validating" a signed JWS.
		if jws.UnprotectedHeader().Algorithm() != "none" {
			return ErrAuthNotNone
		}

		// RFC 7518 § 3.6: JWS using "none" algortihm MUST have an empty signature.
		if len(jws.Signature) != 0 {
			return ErrAuthSignaturePresent
		}

		// checks passed, we can use this signature
		return nil
	})
}

type JWKValidator struct {
	Client    *http.Client
	CacheTime time.Duration
}

func (ja *JWKValidator) Validate(unsafeJws UnverifiedJws) (ValidatedJws, error) {

	return validateEachSignature(unsafeJws, func(jws *validJws) error {

		// RFC 7515 § 4.1.11: Receiver MUST validate extensions listed in crit.
		// this authenticator doesn't support any extensions
		// if any are listed, we must fail
		if jws.UnprotectedHeader().Critical() != nil {
			return fmt.Errorf("unknown JWS extention: %w", ErrUnknownCritExtension)
		}

		// RFC 7515 § 4.1.1: A JWS must contain an "alg" header.
		algorithm := jws.UnprotectedHeader().Algorithm()
		if algorithm == "" {
			return ErrNoAlgHeader
		}

		// this authenitcator works on remote keys
		jku := jws.ProtectedHeader().JwkSetUrl()
		if jku == "" {
			return ErrNoKeyResolution
		}

		jkuUrl, err := url.Parse(jku)
		if err != nil {
			return fmt.Errorf("unable to parse jku url: %w", err)
		}

		// RFC 7515 § 4.1.2: The jku MUST specific a protocol that provides integrity protection.
		if jkuUrl.Scheme != "https" {
			return ErrJkuUnprotected
		}

		return nil
	})

}
