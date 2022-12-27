package jws

import (
	"encoding/json"
	"testing"
)

var testProtectedHeaders = map[string]*protectedHeader{
	"none": {
		values: &RegisterdJwsHeader{},
	},
}

func Test_signedJws_EncodeFlat(t *testing.T) {
	j := &deprecatedSignedJws{
		SignedPayload: []byte("test"),
		Signature:     []byte("signed, bob"),
		Protected:     testProtectedHeaders["none"],
	}

	out, err := json.Marshal(j)
	if err != nil {
		t.Errorf("error marshalling flattened jws: %v", err)
		return
	}
	t.Log(string(out))
}

func Test_signedJws_EncodeGeneral(t *testing.T) {
	j := &deprecatedSignedJws{
		SignedPayload: []byte("test"),
		Signatures: []*jwsSignature{
			{
				Signature: []byte("signed, bob"),
				Protected: testProtectedHeaders["none"],
			},
		},
	}

	out, err := json.Marshal(j)
	if err != nil {
		t.Errorf("error marshalling general jws: %v", err)
		return
	}
	t.Log(string(out))
}

func Test_signedJws_String(t *testing.T) {
	j := &deprecatedSignedJws{
		SignedPayload: []byte("test2"),
		Protected:     testProtectedHeaders["none"],
	}

	s := j.String()
	t.Log(s)
}

func Test_protectedHeader_Bidirectional_Serialize(t *testing.T) {
	tests := []struct {
		name    string
		h       *protectedHeader
		wantErr bool
	}{
		{
			name: "simple",
			h: &protectedHeader{
				values: &RegisterdJwsHeader{
					Algorithm: "none",
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			text, marshalErr := tt.h.MarshalText()
			if marshalErr != nil {
				t.Fatalf("protectedHeader.MarshalText error: %v", marshalErr)
				return
			}

			t.Logf("protectedHeader serialized val=%s", text)

			h2 := protectedHeader{}
			if unmarshalErr := h2.UnmarshalText(text); unmarshalErr != nil {
				t.Fatalf("protectedHeader.UnmarshalText error: %v", unmarshalErr)
			}

			if tt.h.values.Algorithm != h2.values.Algorithm {
				t.Error("Remarshalled algorithm did not match")
			}
		})
	}
}
