package jws

import (
	"fmt"
	"reflect"

	"go.burian.dev/auth/jwk"
)

type JOSEHeader interface {
	ProtectedHeader() Header
	UnprotectedHeader() Header
}

type Header interface {
	Get(string) any

	Algorithm() string
	Critical() []string

	Type() string
	ContentType() string

	JwkSetUrl() string
	Jwk() jwk.JWK
	KeyId() string
}

type jwsHeaderReader struct {
	jws       *validJws
	protected bool
}

func (reader *jwsHeaderReader) Get(name string) any {
	val, ok := reader.jws.Protected[name]
	if ok {
		return val
	}
	if !ok && reader.protected {
		return nil
	}

	return reader.jws.Unprotected[name]
}

// only ever call this if you know what type you're expecting
// i.e. it's a registered header that's been through
// validateKnownTypes beforehand
func (r *jwsHeaderReader) getString(name string) string {
	prop := r.Get(name)
	if prop == nil {
		return ""
	}

	return prop.(string)
}

// The registered "alg" header
func (r *jwsHeaderReader) Algorithm() string {
	return r.getString("alg")
}

// The registered "crit" header
func (r *jwsHeaderReader) Critical() []string {
	crit := r.Get("crit")
	if crit == nil {
		return nil
	}

	return crit.([]string)
}

// The registered "typ" header
func (r *jwsHeaderReader) Type() string {
	return r.getString("typ")
}

// The registerd "cty" header
func (r *jwsHeaderReader) ContentType() string {
	return r.getString("cty")
}

func (r *jwsHeaderReader) JwkSetUrl() string {
	return r.getString("jku")
}

func (r *jwsHeaderReader) Jwk() jwk.JWK {
	// uh
	// todo
	panic("unimplemented")
}
func (r *jwsHeaderReader) KeyId() string {
	return r.getString("kid")
}

// this is a mess, but seems to be the best way to verify that all
// the headers in the JWS that we need to know about are the types
// we expect them to be without having to do cast checks
// for every single getter.
// also lets us fail at decode time rather than get time
func validateKnownTypes(header map[string]any) error {
	stringType := reflect.TypeOf("")
	stringSliceType := reflect.SliceOf(stringType)
	nestedObjectType := reflect.TypeOf(make(map[string]any))

	expectedTypes := map[string]reflect.Type{
		"alg":  stringType,
		"crit": stringSliceType,
		"typ":  stringType,
		"cty":  stringType,
		"jku":  stringType,
		"jwk":  nestedObjectType,
	}

	for name, expectType := range expectedTypes {
		val, set := header[name]
		if !set {
			continue
		}
		if reflect.TypeOf(val) != expectType {
			return fmt.Errorf("header member %s should be a %s, was %s",
				name, expectType, reflect.TypeOf(val),
			)
		}
	}

	return nil
}
