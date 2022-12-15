package jws

type JOSEHeader interface {
	ProtectedHeader() Header
	UnprotectedHeader() Header
}

type Header interface {
	Has(string) bool
	Get(string) string

	//Lookup(string) any
}

// registered JWS headers and known extensions
type registerdHeader struct {
	Algorithm string   `json:"alg,omitempty"`
	Critical  []string `json:"crit,omitempty"`

	Type        string `json:"typ,omitempty"`
	ContentType string `json:"cty,omitempty"`

	JWKSetUrl string `json:"jku,omitempty"`
	JWK       string `json:"jwk,omitempty"`
	KeyId     string `json:"kid,omitempty"`
}

type jwsHeaderReader struct {
	jws       *validatedJws
	protected bool
}

func (hr *jwsHeaderReader) Get(key string) (val string) {
	val, _ = hr.findEither(key)
	return
}

func (hr *jwsHeaderReader) Has(key string) (has bool) {
	_, has = hr.findEither(key)
	return
}

func (hr *jwsHeaderReader) findEither(key string) (string, bool) {
	// start by reading the protected header since that's always valid
	val := hr.find(hr.jws.Protected, key)

	// if it's been found, return it
	if val != "" {
		return val, true
	}

	// if we aren't looking at unprotected headers, bail
	if hr.protected {
		return "", false
	}

	// try again with the unprotected header
	val = hr.find(hr.jws.Unprotected, key)

	// return whatever we got at this point
	// we'll ignore the value returned from find just in case
	// the implementation sets something
	if val == "" {
		return "", false
	}
	return val, true
}

func (hr *jwsHeaderReader) find(h *registerdHeader, key string) string {
	switch key {
	case "alg":
		return h.Algorithm
	case "crit":
		// can't return, it's an array
	case "typ":
		return h.Type
	case "cty":
		return h.ContentType
	case "jku":
		return h.JWKSetUrl
	case "jwk":
		// can't return, it's an object
	case "kid":
		return h.KeyId
	}
	return ""
}
