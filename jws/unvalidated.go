package jws

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode"
)

type UnverifiedJws interface {
	GetSignatures() []*signedJwsSignature
	GetPayload() []byte
}

// rawJws is essentially the same as a signedJws, but has both
// the flattened and general encoding fields available for decoding
type rawJws struct {
	Payload    string                `json:"payload"`
	Protected  string                `json:"protected"`
	Signature  string                `json:"signature"`
	Header     map[string]any        `json:"header"`
	Signatures []*signedJwsSignature `json:"signatures"`
}

// ParseJws takes a JWS in any valid encoding, and returns a
// decoded, but not cryptographically verified JWS.
//
// Can parse dot-separated compact string encoding, or JSON
func ParseJws(encodedJws []byte) (UnverifiedJws, error) {
	return parseJwsAnyEncoding(encodedJws)
}

func parseJwsAnyEncoding(encodedJws []byte) (*signedJws, error) {
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
func decodeCompact(data []byte) (*signedJws, error) {
	// we can treat the compact encoding as a string for simplicity
	compactString := string(data)

	parts := strings.Split(compactString, ".")
	if len(parts) != 3 {
		return nil, ErrInvalidCompactEncoding
	}

	// unpack it to General signed encoding to make things simpler
	signed := &signedJws{
		Payload: parts[1],
		Signatures: []*signedJwsSignature{
			{
				Protected: parts[0],
				Signature: parts[2],
			},
		},
	}

	// common validateion
	if err := validateDecodedJws(signed); err != nil {
		return nil, err
	}

	return signed, nil

}

// First steps of
// RFC 7515 § 5.2: Message Signature or MAC Validation.
// 5.2.1 parse and verify JSON flattened and general
func decodeJson(data []byte) (*signedJws, error) {
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

	// restructure it into a signedJws
	signed := &signedJws{
		Payload: raw.Payload,
	}

	// unpack either a general serialization, verifying we don't have
	// duplicate fields, or a flattened serialization into a general
	// structure
	if len(raw.Signatures) > 0 {
		if raw.Protected != "" || len(raw.Header) != 0 || raw.Signature != "" {
			return nil, errors.New("bad general encoding: has flattened and general members")
		}
		signed.Signatures = raw.Signatures
	} else {
		unflattenedSig := &signedJwsSignature{
			Protected: raw.Protected,
			Header:    raw.Header,
			Signature: raw.Signature,
		}
		signed.Signatures = append(signed.Signatures, unflattenedSig)
	}

	// common validateion
	if err := validateDecodedJws(signed); err != nil {
		return nil, fmt.Errorf("jws validation failed: %w", err)
	}

	return signed, nil
}

// Performs some of the validation required in
// RFC 7515 § 5.2: Message Signature or MAC Validation.
// 5.2.2
// 5.2.3
// 5.2.4
// 5.2.6
// 5.2.7
func validateDecodedJws(jws *signedJws) error {

	// verify the Payload is a valid base64 object
	// 5.2.6
	payloadBytes := make([]byte, base64url.DecodedLen(len(jws.Payload)))
	_, err := base64url.Decode(payloadBytes, []byte(jws.Payload))
	if err != nil {
		return fmt.Errorf("bad payload encoding: %w", err)
	}

	// We have to verify each signature
	for sigId, sig := range jws.Signatures {

		// ensure the protected header is a valid
		// base64 encoded JSON object
		// 5.2.2 & 5.2.3
		// TODO: need to validate requirements of 5.2.2 with more rigour
		protectedBytes := make([]byte, base64url.DecodedLen(len(sig.Protected)))
		_, err := base64url.Decode(protectedBytes, []byte(sig.Protected))
		if err != nil {
			return fmt.Errorf("bad protected header encoding in signature %d: %w", sigId, err)
		}

		jose := make(map[string]any)

		// unmarshal the bytes into a header struct
		err = json.Unmarshal(protectedBytes, &jose)
		if err != nil {
			return fmt.Errorf("bad JSON encoding for protected header in signature %d: %w", sigId, err)
		}

		// checking for duplicates in the jose header
		// 5.2.4
		for key := range sig.Header {
			if _, set := jose[key]; set {
				return fmt.Errorf("JOSE header for signature %d contains duplicate member: %s", sigId, key)
			}

			// merge them together for later
			jose[key] = sig.Header[key]
		}

		// ensure the signature is valid base64 encoded bytes
		// 5.2.7
		sigBytes := make([]byte, base64url.DecodedLen(len(sig.Signature)))
		_, err = base64url.Decode(sigBytes, []byte(sig.Signature))
		if err != nil {
			return fmt.Errorf("bad signature encoding in signature %d: %w", sigId, err)
		}

		// an additional check for our own sanity
		// make sure registered header types are what we expect them to be
		err = validateKnownTypes(jose)
		if err != nil {
			return fmt.Errorf("invalid registered header: %w", err)
		}
	}

	// all checks pass
	return nil

}
