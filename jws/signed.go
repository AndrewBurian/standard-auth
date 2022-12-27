package jws

import (
	"encoding/json"
	"fmt"
)

// SignedJws is a JWS ready to be sent
//
// This exports only the functions required to encode the JWS
// to compact, JSON, and JSON Flat encoding.
//
// There is no introspection of the SignedJws available. If you
// are trying to read decode and read a JWS, use a Validator to
// create a ValidatedJws.
type SignedJws interface {
	CompactEncode() (string, error)
	JSONEncode() ([]byte, error)
}

// RFC 7515 § 7.2.1: General JWS Serialization Syntax.
// MUST have payload even if it's an empty string
// MUST have signatures member
type signedJws struct {
	Payload    string                `json:"payload"`
	Signatures []*signedJwsSignature `json:"signatures"`
}

// RFC 7515 § 7.2.1: General JWS Serialization Syntax for signatures member
// Protected MUST be omitted if empty
// Header MUST be omitted if empty
// Signature MUST be present even if it's the empty string
type signedJwsSignature struct {
	Protected string         `json:"protected,omitempty"`
	Signature string         `json:"signature"`
	Header    map[string]any `json:"header,omitempty"`

	// convinience for internal functions that would need to
	// convert protected otherwise
	protectedRaw map[string]any
}

// RFC 7515 § 7.2.1: Flattened JWS Serialization Sytax.
// same inclusion rules as general syntax above
type flattenedJws struct {
	Payload   string         `json:"payload"`
	Protected string         `json:"protected,omitempty"`
	Signature string         `json:"signature"`
	Header    map[string]any `json:"header,omitempty"`
}

// CompactEncode encodes a SignedJws into the compact string encoding
// designed for URL query components and HTTP Headers.
//
// Compact encoding does not support JWS' with more than one signature
// or any unprotected headers. CompactEncode will return an error
// in these cases.
//
// Implements RFC 7515 § 7.1 Compact Serialization
func (sj *signedJws) CompactEncode() (string, error) {
	if len(sj.Signatures) == 0 {
		// should never happen, cannot instantiate a signedJws literally
		// so something has gone wrong
		panic("signedJws is unsigned, which should not be possible")
	}

	// cannot use compact encoding if there's more than one signature
	if len(sj.Signatures) > 1 {
		return "", ErrTooManySignatures
	}
	sig := sj.Signatures[0]

	// cannot have unprotected headers in compact encoding
	if sig.Header == nil {
		return "", ErrInvalidCompactEncoding
	}

	// there needs to be a protected header
	if sig.Protected == "" {
		// should also never happen. Even a JWS with alg: none
		// will have a "protected" header that specifies that
		panic("signedJws has no protected header, which should not be possible")
	}

	// companct encoding is just dot separated base64 blobs, which
	// is what the builder has already set in the fields.
	return fmt.Sprintf("%s.%s.%s",
			sig.Protected, sj.Payload, sig.Signature),
		nil
}

// JSONEncode encodes a SignedJws into a JSON encoding.
//
// JSON encoded JWS' support multiple signatures, unprotected headers,
// and different protected and unprotected headers for each signature.
//
// If only one signature is present, the Flattened JWS JSON Serialization
// is used.
// Otherwise the General JWS JSON Serialization is used.
//
// Implements RFC 7515 § 7.2.1 and 7.2.2 JSON Serializations
func (sj *signedJws) JSONEncode() ([]byte, error) {

	// sanity checks
	if len(sj.Signatures) == 0 {
		panic("signedJws is unsigned, which should not be possible")
	}

	// see if we can use flattened encoding
	if len(sj.Signatures) == 1 {
		sig := sj.Signatures[0]
		flat := &flattenedJws{
			Payload:   sj.Payload,
			Header:    sig.Header,
			Protected: sig.Protected,
			Signature: sig.Signature,
		}

		return json.Marshal(flat)
	}

	// otherwise marshal the full thing
	return json.Marshal(sj)
}

// function wrapper for interface conformance
func (sj *signedJws) GetSignatures() []*signedJwsSignature {
	return sj.Signatures
}

func (sj *signedJws) GetPayload() []byte {
	return []byte(sj.Payload)
}
