package jws

import (
	"errors"
)

var (
	ErrNoSignatures           = errors.New("no valid signatures in JWS object")
	ErrTooManySignatures      = errors.New("cannot have more that 1 signature for compact encoding")
	ErrBadHeader              = errors.New("must have protected header values and no unprotected header for compact encoding")
	ErrInvalidCompactEncoding = errors.New("unable to parse input as JWS compact encoding")
)

// // CompactEncode returns a URL safe string representing the JWS in Compact format
// // as described in RFC 7515 § 7.1
// func (jws *deprecatedSignedJws) CompactEncode() (string, error) {

// 	// Cannot encode mulitple signatures
// 	if jws.Signatures != nil {
// 		return "", ErrTooManySignatures
// 	}

// 	// Cannot encode unprotected headers
// 	if jws.Unprotected != nil {
// 		return "", ErrBadHeader
// 	}

// 	signature, err := jws.Signature.MarshalText()
// 	if err != nil {
// 		return "", err
// 	}
// 	payload, err := jws.SignedPayload.MarshalText()
// 	if err != nil {
// 		return "", err
// 	}
// 	header, err := jws.Protected.MarshalText()
// 	if err != nil {
// 		return "", err
// 	}

// 	return fmt.Sprintf("%s.%s.%s", header, payload, signature), nil
// }

// func compactDecode(s string) (*deprecatedSignedJws, error) {
// 	parts := strings.Split(s, ".")
// 	if len(parts) != 3 {
// 		return nil, ErrInvalidCompactEncoding
// 	}

// 	jws := &deprecatedSignedJws{}

// 	if err := jws.Protected.UnmarshalText([]byte(parts[0])); err != nil {
// 		return nil, ErrInvalidCompactEncoding
// 	}

// 	if err := jws.SignedPayload.UnmarshalText([]byte(parts[1])); err != nil {
// 		return nil, ErrInvalidCompactEncoding
// 	}

// 	if err := jws.Signature.UnmarshalText([]byte(parts[2])); err != nil {
// 		return nil, ErrInvalidCompactEncoding
// 	}

// 	return jws, nil
// }

// func (jws *deprecatedSignedJws) JSONEncode() ([]byte, error) {
// 	return json.Marshal(jws)
// }

// func jsonDecode(b []byte) (*deprecatedSignedJws, error) {
// 	jws := &deprecatedSignedJws{}
// 	if err := json.Unmarshal(b, jws); err != nil {
// 		return nil, err
// 	}
// 	return jws, nil
// }

// func (jws *deprecatedSignedJws) String() string {
// 	if s, err := jws.CompactEncode(); err == nil {
// 		return s
// 	}

// 	if json, err := jws.JSONEncode(); err == nil {
// 		return string(json)
// 	}

// 	return fmt.Sprintf("invalid %T", jws)

// }

// // protectedHeader is just a regular registered header with custom text marhsalling
// // to allow for url safe base64 encoding and decoding of the json object
// type protectedHeader struct {
// 	values *RegisterdJwsHeader
// }

// func (h *protectedHeader) MarshalText() ([]byte, error) {

// 	// if the header isn't set, marshal to an empty octet sequence
// 	if h == nil || h.values == nil {
// 		return []byte{}, nil
// 	}

// 	jStr, err := json.Marshal(h.values)
// 	if err != nil {
// 		return nil, err
// 	}

// 	buf := make([]byte, base64.RawURLEncoding.EncodedLen(len(jStr)))
// 	base64.RawURLEncoding.Encode(buf, jStr)
// 	return buf, nil
// }

// func (h *protectedHeader) UnmarshalText(b []byte) error {

// 	jBytes := make([]byte, base64.RawURLEncoding.DecodedLen(len(b)))
// 	_, err := base64.RawURLEncoding.Decode(jBytes, b)
// 	if err != nil {
// 		return err
// 	}

// 	h.values = &RegisterdJwsHeader{}
// 	return json.Unmarshal(jBytes, h.values)
// }

// // This type and it's corresponding text unmarshaller are purely to make sure we use
// // base64 with url encoding instead of std encoding
// type opaqueData []byte

// var _ encoding.TextMarshaler = opaqueData{}

// func (d opaqueData) MarshalText() ([]byte, error) {
// 	buf := make([]byte, base64.RawURLEncoding.EncodedLen(len(d)))
// 	base64.RawURLEncoding.Encode(buf, d)
// 	return buf, nil
// }

// func (d opaqueData) UnmarshalText(b []byte) error {
// 	d = make([]byte, base64.RawURLEncoding.EncodedLen(len(b)))
// 	_, err := base64.RawURLEncoding.Decode(b, b)
// 	return err
// }

// func (d opaqueData) Empty() bool {
// 	// TODO: Validate this approach with different serializations
// 	return len(d) == 0
// }
