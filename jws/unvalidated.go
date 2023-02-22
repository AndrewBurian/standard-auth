package jws

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode"
)

var (
	ErrInvalidCompactEncoding = errors.New("unable to parse input as JWS compact encoding")
)

type UnverifiedJws interface {
	GetSignatures() []*unsafeJwsSignature
	GetPayload() []byte
}

// rawJws is essentially the same as a signedJws, but has both
// the flattened and general encoding fields available for decoding
type rawJws struct {
	PayloadEncoded   string             `json:"payload"`
	Signatures       []*rawJwsSignature `json:"signatures"`
	*rawJwsSignature                    // anonymous signature at the root for flattened
}

type rawJwsSignature struct {
	ProtectedHeaderEncoded string         `json:"protected,omitempty"`
	UnprotectedHeader      map[string]any `json:"header,omitempty"`
	SignatureEncoded       string         `json:"signature"`
}

type unsafeJws struct {
	payloadBytes []byte
	signatures   []*unsafeJwsSignature
}

type unsafeJwsSignature struct {
	unprotectedHeader map[string]any
	protectedHeader   map[string]any
	signatureBytes    []byte
	signingInput      []byte
}

func (uj *unsafeJws) GetPayload() []byte {
	return uj.payloadBytes
}

func (uj *unsafeJws) GetSignatures() []*unsafeJwsSignature {
	return uj.signatures
}

// ParseJws takes a JWS in any valid encoding, and returns a
// decoded, but not cryptographically verified JWS.
//
// Can parse dot-separated compact string encoding, or JSON
func ParseJws(encodedJws []byte) (UnverifiedJws, error) {
	return parseJwsAnyEncoding(encodedJws)
}

func parseJwsAnyEncoding(encodedJws []byte) (*unsafeJws, error) {
	if len(encodedJws) == 0 {
		return nil, errors.New("invalid jws: zero-length or nil data")
	}

	// quick way to verify what encoding it is, does it have an
	// opening '{', which must be present to be valid JSON, and
	// cannot be present for compact encoding
	for i := range encodedJws {
		if unicode.IsSpace(rune(encodedJws[i])) {
			continue
		}
		if encodedJws[i] == '{' {
			return decodeJson(encodedJws)
		}
		if i > 0 {
			return nil, errors.New("invalid input: leading whitespace for non JSON encoded jws")
		}
		return decodeCompact(encodedJws)
	}
	// should never reach here
	panic("jws parsing reached an unreachable state when choosing between serializations")
}

// First steps of
// RFC 7515 § 5.2: Message Signature or MAC Validation.
// 5.2.1 parse and verify compact
func decodeCompact(data []byte) (*unsafeJws, error) {
	// we can treat the compact encoding as a string for simplicity
	compactString := string(data)

	parts := strings.Split(compactString, ".")
	if len(parts) != 3 {
		return nil, ErrInvalidCompactEncoding
	}

	// unpack it to General signed encoding to make things simpler
	raw := &rawJws{
		PayloadEncoded: parts[1],
		Signatures: []*rawJwsSignature{
			{
				ProtectedHeaderEncoded: parts[0],
				SignatureEncoded:       parts[2],
			},
		},
	}

	// common validateion
	unsafe, err := decodedRawJws(raw)
	if err != nil {
		return nil, err
	}

	return unsafe, nil

}

// First steps of
// RFC 7515 § 5.2: Message Signature or MAC Validation.
// 5.2.1 parse and verify JSON flattened and general
func decodeJson(data []byte) (*unsafeJws, error) {
	raw := &rawJws{}

	{
		// while not strictly required by the standard, we forbid
		// any objects that have additional fields
		strictDecoder := json.NewDecoder(bytes.NewBuffer(data))
		strictDecoder.DisallowUnknownFields()
		err := strictDecoder.Decode(raw)
		if err != nil {
			return nil, fmt.Errorf("bad jws json encoding: %w", err)
		}
	}

	// unpack either a general serialization, verifying we don't have
	// duplicate fields, or a flattened serialization into a general
	// structure
	if len(raw.Signatures) > 0 || raw.rawJwsSignature != nil {
		return nil, errors.New("bad general encoding: has flattened and general members")
	}
	if raw.rawJwsSignature != nil {
		raw.Signatures = append(raw.Signatures, raw.rawJwsSignature)
	}

	// common validateion
	decoded, err := decodedRawJws(raw)
	if err != nil {
		return nil, fmt.Errorf("jws decoding failed: %w", err)
	}

	return decoded, nil
}

// Decodes a raw JWs
// Performs some of the validation required in
// RFC 7515 § 5.2: Message Signature or MAC Validation.
// 5.2.2
// 5.2.3
// 5.2.4
// 5.2.6
// 5.2.7
// output is still untrusted since we don't yet verify
// the actual signature
func decodedRawJws(jws *rawJws) (*unsafeJws, error) {

	decoded := new(unsafeJws)
	var err error

	// verify the Payload is a valid base64 object
	// 5.2.6
	decoded.payloadBytes = make([]byte, base64url.DecodedLen(len(jws.PayloadEncoded)))
	_, err = base64url.Decode(decoded.payloadBytes, []byte(jws.PayloadEncoded))
	if err != nil {
		return nil, fmt.Errorf("bad payload encoding: %w", err)
	}

	// We have to verify each signature
	for sigId, sig := range jws.Signatures {

		nextSig := new(unsafeJwsSignature)

		// ensure the protected header is a valid
		// base64 encoded JSON object
		// 5.2.2 & 5.2.3
		// TODO: need to validate requirements of 5.2.2 with more rigour
		protectedBytes := make([]byte, base64url.DecodedLen(len(sig.ProtectedHeaderEncoded)))
		_, err := base64url.Decode(protectedBytes, []byte(sig.ProtectedHeaderEncoded))
		if err != nil {
			return nil, fmt.Errorf("bad protected header encoding in signature %d: %w", sigId, err)
		}

		nextSig.protectedHeader = make(map[string]any)

		// unmarshal the bytes into a header struct
		err = json.Unmarshal(protectedBytes, nextSig)
		if err != nil {
			return nil, fmt.Errorf("bad JSON encoding for protected header in signature %d: %w", sigId, err)
		}

		nextSig.unprotectedHeader = sig.UnprotectedHeader

		// checking for duplicates in the jose header
		// 5.2.4
		for key := range nextSig.unprotectedHeader {
			if _, set := nextSig.protectedHeader[key]; set {
				return nil, fmt.Errorf("JOSE header for signature %d contains duplicate member: %s", sigId, key)
			}
		}

		// ensure the signature is valid base64 encoded bytes
		// 5.2.7
		nextSig.signatureBytes = make([]byte, base64url.DecodedLen(len(sig.SignatureEncoded)))
		_, err = base64url.Decode(nextSig.signatureBytes, []byte(sig.SignatureEncoded))
		if err != nil {
			return nil, fmt.Errorf("bad signature encoding in signature %d: %w", sigId, err)
		}

		// an additional check for our own sanity
		// make sure registered header types are what we expect them to be
		err = validateKnownTypes(nextSig.protectedHeader)
		if err != nil {
			return nil, fmt.Errorf("invalid registered header in protected headers in signature %d: %w", sigId, err)
		}
		err = validateKnownTypes(nextSig.unprotectedHeader)
		if err != nil {
			return nil, fmt.Errorf("invalid registered header in unprotected headers in signature %d: %w", sigId, err)
		}
	}

	// all checks pass
	return decoded, nil

}
