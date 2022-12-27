package jws

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"

	"go.burian.dev/auth/jwk"
)

var base64url = base64.RawURLEncoding

var (
	ErrDuplicateHeader = errors.New("duplicate header present in computed JOSE header, invalid")
	ErrAlreadySigned   = errors.New("builder already signed, modifying payload or protected header has no effect")
)

// JWSBuilder is used to construct a JWS signed by your application.
//
// Attempting to modify headers or payload after the first call to Sign
// produces an error. To create different JWS' use separate Builers.
//
// It is valid to repeatedly call Sign with different JWK Signers to
// create multiple JWS', each signed one with different keys
//
// To create a single JWS signed with multiple keys, use AddSignature
// on the JWS created by Sign.
//
// The zero value is a builder ready for use.
//
// Implements RFC 7515 § 5.1 Message Signature or MAC Computation steps.
type JWSBuilder struct {
	payload         bytes.Buffer
	protectedHeader map[string]any
	written         bool
}

// Write appends the given data to the payload
//
// Returns ErrAlreadySigned if the builder has already signed and
// generated a JWS
func (b *JWSBuilder) Write(dat []byte) (int, error) {
	if b.written {
		return 0, ErrAlreadySigned
	}
	return b.payload.Write(dat)
}

// WriteString appends the given string to the payload
//
// Returns ErrAlreadySigned if the builder has already signed and
// generated a JWS
func (b *JWSBuilder) WriteString(dat string) (int, error) {
	if b.written {
		return 0, ErrAlreadySigned
	}
	return b.payload.WriteString(dat)
}

// SetPayload sets the payload to be used in the JWS, resetting
// any existing data set by Write or Set calls.
//
// Call SetPayload with a nil or zero-length slice to reset the
// payload contents
//
// Returns ErrAlreadySigned if the builder has already signed and
// generated a JWS
func (b *JWSBuilder) SetPayload(payload []byte) error {
	if b.written {
		return ErrAlreadySigned
	}

	b.payload = bytes.Buffer{}
	_, err := b.payload.Write(payload)
	return err
}

// SetPayloadObject sets the payload to be used in the JWS, to the JSON
// serialization of the provided interface
// resetting any existing data set by Write or Set calls.
//
// # Payload may implement json.Marhsaler to control the serialization
//
// Returns ErrAlreadySigned if the builder has already signed and
// generated a JWS
func (b *JWSBuilder) SetPayloadObject(payload any) error {
	if b.written {
		return ErrAlreadySigned
	}

	bytes, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	return b.SetPayload(bytes)
}

func (b *JWSBuilder) SetHeader(key string, value any) error {
	if b.written {
		return ErrAlreadySigned
	}
	if b.protectedHeader == nil {
		b.protectedHeader = make(map[string]any)
	}
	b.protectedHeader[key] = value
	return nil
}

func (b *JWSBuilder) HasHeader(key string) bool {
	_, set := b.protectedHeader[key]
	return set
}

func (b *JWSBuilder) Sign(ctx context.Context, signer jwk.Signer, addHeader map[string]any) (*signedJws, error) {

	// RFC 7515 § 5.1: Prepare a JWS Signature or HMAC.
	signed := &signedJws{}

	// 5.1.1 Create the content to be used as the JWS Payload
	payload := b.payload.Bytes()

	// 5.1.2 Compute the encoded payload value
	// handled by the opaqueData custom text marshaler
	signed.Payload = base64.RawURLEncoding.EncodeToString(payload)

	// we farm the rest off to AddSignature to dry up the code
	err := b.AddSignature(ctx, signed, signer, addHeader)
	if err != nil {
		return nil, err
	}

	b.written = true
	return signed, nil

}

func (b *JWSBuilder) AddSignature(ctx context.Context, jws *signedJws, signer jwk.Signer, addHeader map[string]any) error {

	// we'll fill out this signature over the course of this function
	sig := &signedJwsSignature{}

	// 5.1.3 Create JOSE header(s)
	// we do this just to ensure there's no overlap in the protected
	// and unprotected headers
	jose := make(map[string]any)

	for key, val := range b.protectedHeader {
		jose[key] = val
	}

	for key, val := range addHeader {
		if _, exists := jose[key]; exists {
			return ErrDuplicateHeader
		}
		jose[key] = val
	}

	// add the alg header from the jwk
	jose["alg"] = ""
	// TODO

	// 5.1.4 Compute encoded header
	headerJsonBytes, err := json.Marshal(jose)
	if err != nil {
		return err
	}

	sig.Protected = base64.RawURLEncoding.EncodeToString(headerJsonBytes)

	// 5.1.5 Compute the signature over
	// (JWS Protected Header) || '.' || (JWS Payload)
	signingInput := bytes.Buffer{}
	signingInput.WriteString(sig.Protected)
	signingInput.WriteRune('.')
	signingInput.WriteString(jws.Payload)

	newSignatureData, err := signer.Sign(ctx, signingInput.Bytes())
	if err != nil {
		return err
	}

	// 5.1.6 encoded signature value
	sig.Signature = base64.RawURLEncoding.EncodeToString(newSignatureData)

	// 5.1.7 referrs to looping, which we do on demand
	// instead we just add this signature to the list

	jws.Signatures = append(jws.Signatures, sig)

	return nil
}
