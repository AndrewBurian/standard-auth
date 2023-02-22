package jws

import (
	"errors"
	"fmt"
	"reflect"
	"testing"
)

func jsonEn(protected, header map[string]any, sig, payload []byte) (string, *unsafeJws) {

}

func Test_parseJwsAnyEncoding(t *testing.T) {

	tests := []struct {
		name      string
		input     []byte
		want      *unsafeJws
		wantErr   bool
		wantErrIs error
	}{
		{
			// sample from RFC 7515 § 3.3: Example JWS.
			name:  "valid compact",
			input: []byte(`eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk`),
			want: &unsafeJws{
				PayloadEncoded: `eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ`,
				Signatures: []*unsafeJwsSignature{
					{
						protectedHeader: map[string]any{
							"iss":                        "joe",
							"exp":                        1300819380,
							"http://example.com/is_root": true,
						},
						ProtectedHeaderEncoded: `eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9`,
						UnprotectedHeader:      nil,
						SignatureEncoded:       `dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk`,
					},
				},
			},
		},
		{
			name: "valid flattened",
			input: []byte(`
				{
					"protected": "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9",
					"payload": "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
					"signature": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
				}
			`),
			want: &unsafeJws{
				PayloadEncoded: `eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ`,
				Signatures: []*unsafeJwsSignature{
					{
						ProtectedHeaderEncoded: `eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9`,
						UnprotectedHeader:      nil,
						SignatureEncoded:       `dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk`,
					},
				},
			},
		},
		{
			name: "valid general single sig",
			input: []byte(`
				{
					"payload": "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
					"signatures": [
						{
							"protected": "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9",
							"signature": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
						}
					]
				}
			`),
			want: &unsafeJws{
				PayloadEncoded: `eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ`,
				Signatures: []*unsafeJwsSignature{
					{
						ProtectedHeaderEncoded: `eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9`,
						UnprotectedHeader:      nil,
						SignatureEncoded:       `dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk`,
					},
				},
			},
		},
		{
			name: "valid general multiple sig",
			input: []byte(`
				{
					"payload": "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
					"signatures": [
						{
							"protected": "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9",
							"signature": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
						},
						{
							"protected": "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9",
							"signature": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
						}
					]
				}
			`),
			want: &unsafeJws{
				PayloadEncoded: `eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ`,
				Signatures: []*unsafeJwsSignature{
					{
						ProtectedHeaderEncoded: `eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9`,
						UnprotectedHeader:      nil,
						SignatureEncoded:       `dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk`,
					},
					{
						ProtectedHeaderEncoded: `eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9`,
						UnprotectedHeader:      nil,
						SignatureEncoded:       `dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk`,
					},
				},
			},
		},
		{
			name:    "invalid compact leading whitespace",
			input:   []byte(` eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9`),
			wantErr: true,
		},
		{
			name:    "invalid compact internal whitespace",
			input:   []byte(`eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9 .  eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9`),
			wantErr: true,
		},
		{
			name:    "invalid empty input",
			input:   []byte(``),
			wantErr: true,
		},
		{
			name:    "invalid compact too few segments",
			input:   []byte(`eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ`),
			wantErr: true,
		},
		{
			name:    "invalid compact too many segments",
			input:   []byte(`eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjE.zMDA4MTkzODAsDQogImh0dHA6Ly9l.eGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ`),
			wantErr: true,
		},
		{
			name:    "invalid json bad json",
			input:   []byte(`{foo, bar}`),
			wantErr: true,
		},
		{
			name: "invalid general json flat and general fields",
			input: []byte(`
				{
					"payload": "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
					"protected": "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9",
					"signatures": [
						{
							"protected": "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9",
							"signature": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
						},
						{
							"protected": "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9",
							"signature": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
						}
					]
				}
			`),
			wantErr: true,
		},
		{
			name: "invalid protected header not json",
			// header is BASE64RUL(`"alg":"foo"`) with no braces
			input: []byte(`
				{
					"protected": "ImFsZyI6ImZvbyI",
					"payload": "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
					"signature": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
				}
			`),
			wantErr: true,
		},
		{
			name: "invalid protected header not base64",
			input: []byte(`
				{
					"protected": "{\"alg\": 1}",
					"payload": "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
					"signature": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
				}
			`),
			wantErr: true,
		},
		{
			name: "invalid duplicate jose header names",
			input: []byte(`
				{
					"protected": "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9",
					"payload": "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
					"signature": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
					"header": {
						"alg": "something"
					}
				}
			`),
			wantErr: true,
		},
		{
			name: "valid flattened with extra headers",
			input: []byte(`
				{
					"protected": "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9",
					"payload": "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
					"signature": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
					"header": {
						"kid": "mykey"
					}
				}
			`),
			want: &unsafeJws{
				PayloadEncoded: `eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ`,
				Signatures: []*unsafeJwsSignature{
					{
						ProtectedHeaderEncoded: `eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9`,
						UnprotectedHeader: map[string]any{
							"kid": "mykey",
						},
						SignatureEncoded: `dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk`,
					},
				},
			},
		},
		{
			name: "valid general multiple sig extra headers",
			input: []byte(`
				{
					"payload": "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
					"signatures": [
						{
							"protected": "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9",
							"signature": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
							"header": {
								"kid": "key1"
							}
						},
						{
							"protected": "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9",
							"signature": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
							"header": {
								"kid": "key2"
							}
						}
					]
				}
			`),
			want: &unsafeJws{
				PayloadEncoded: `eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ`,
				Signatures: []*unsafeJwsSignature{
					{
						ProtectedHeaderEncoded: `eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9`,
						UnprotectedHeader: map[string]any{
							"kid": "key1",
						},
						SignatureEncoded: `dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk`,
					},
					{
						ProtectedHeaderEncoded: `eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9`,
						UnprotectedHeader: map[string]any{
							"kid": "key2",
						},
						SignatureEncoded: `dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk`,
					},
				},
			},
		},
		{
			name: "invalid signature not base64",
			input: []byte(`
				{
					"protected": "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9",
					"payload": "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
					"signature": "is good, trust me"
				}
			`),
			wantErr: true,
		},
		{
			name: "invalid registered header value type",
			input: []byte(`
				{
					"header" : {
						"kid": 7
					},
					"protected": "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9",
					"payload": "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
					"signature": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
				}
			`),
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseJwsAnyEncoding(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseJws() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil && tt.wantErr {
				if tt.wantErrIs == nil {
					return
				}
				if !errors.Is(err, tt.wantErrIs) {
					t.Errorf("Expected error to be %v, was %v", tt.wantErrIs, err)
				}
				return
			}
			if compError := compareJws(got, tt.want); compError != nil {
				t.Error(compError)
			}
		})
	}
}

func compareJws(have, want *unsafeJws) error {
	if have == nil {
		return fmt.Errorf("jws is nil")
	}

	if want.PayloadEncoded != have.PayloadEncoded {
		return fmt.Errorf("payload mismatch\n\twant: %s\n\thave: %s",
			want.PayloadEncoded, have.PayloadEncoded)
	}

	if len(want.Signatures) != len(have.Signatures) {
		return fmt.Errorf("number of signatures mismatch:\n\twant: %d\n\thave: %d",
			len(want.Signatures), len(have.Signatures))
	}

	for i := range want.Signatures {
		if want.Signatures[i].ProtectedHeaderEncoded != have.Signatures[i].ProtectedHeaderEncoded {
			return fmt.Errorf("protected header mismatch in signature %d:\n\twant: %s\n\thave: %s", i,
				want.Signatures[i].ProtectedHeaderEncoded,
				have.Signatures[i].ProtectedHeaderEncoded)
		}

		if want.Signatures[i].SignatureEncoded != have.Signatures[i].SignatureEncoded {
			return fmt.Errorf("signature bytes mismatch in signature %d:\n\twant: %s\n\thave: %s", i,
				want.Signatures[i].SignatureEncoded,
				have.Signatures[i].SignatureEncoded)
		}

		if !reflect.DeepEqual(want.Signatures[i].UnprotectedHeader, have.Signatures[i].UnprotectedHeader) {
			return fmt.Errorf("unprotected header mismatch in signature %d:\n\twant: %v\n\thave: %v", i,
				want.Signatures[i].UnprotectedHeader,
				have.Signatures[i].UnprotectedHeader)
		}
	}

	return nil
}
