package jws

import (
	"reflect"
	"testing"

	"encoding/json"
)

func encodedObj(a any) string {
	bytes, err := json.Marshal(a)
	if err != nil {
		panic(err)
	}
	return base64url.EncodeToString(bytes)
}

func TestNoneValidator_Validate(t *testing.T) {
	tests := []struct {
		name      string
		n         *NoneValidator
		input     *signedJws
		want      ValidatedJws
		wantErr   bool
		wantErrIs error
	}{
		{
			name: "valid none compact",
			n:    nil, // unnecessary
			input: &signedJws{
				Payload: "",
				Signatures: []*signedJwsSignature{
					{
						Protected: encodedObj(map[string]string{
							"alg": "none",
						}),
						Signature: "",
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := &NoneValidator{}
			got, err := n.Validate(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("NoneValidator.Validate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NoneValidator.Validate() = %v, want %v", got, tt.want)
			}
		})
	}
}
