package jwk

import (
	"context"
	"encoding/json"
)

type JWK interface {
	Signer(jwa string) (Signer, error)
	Verifier(jwa string) (Verifier, error)

	Encrypter(jwa string) (Encrypter, error)
	Decrypter(jwa string) (Decrypter, error)
}

type Signer interface {
	Sign(ctx context.Context, message []byte) ([]byte, error)
}

type Verifier interface {
	Verify(message, digest []byte) error
}

type Encrypter interface {
	Encrypt(plaintext, aad []byte) ([]byte, error)
}

type Decrypter interface {
	Decrypt(ciphertext, aad []byte) error
}

// jwkStub contains the few fields always returned to identity a key
// as well as the raw JWK data
// A jwk can be unmarshalled into this struct, and will be lazily cast
// to a concrete key implementation on demand
type jwkStub struct {
	Common *JwkCommonHeader

	RawData []byte
}

var _ json.Unmarshaler = &jwkStub{}

//var _ JWK = &jwkStub{}

// Unmarshalling a jwkStub only pulls the common headers
// the original json of the onject is stored to later unmarshal again
// into a complete key implementation
func (js *jwkStub) UnmarshalJSON(data []byte) error {
	js.Common = &JwkCommonHeader{}
	if err := json.Unmarshal(data, js.Common); err != nil {
		return err
	}

	js.RawData = make([]byte, len(data))
	copy(js.RawData, data)

	return nil
}

type JwkCommonHeader struct {
	KeyType       string   `json:"kty"`
	Use           string   `json:"use,omitempty"`
	Algorithm     string   `json:"alg,omitempty"`
	KeyOperations []string `json:"key_ops,omitempty"`
	KeyId         string   `json:"kid,omitempty"`
}

func (js *jwkStub) FullKey() JWK {
	switch js.Common.KeyType {
	case "EC":
		switch js.Common.Algorithm {

		}

	}
	panic("inimplemented")
}

func (js *jwkStub) Signer(jwa string) (Signer, error) {
	js.FullKey()
	panic("inimplemented")
}
