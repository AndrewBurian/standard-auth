package jws

type ValidatedJws interface {
	JOSEHeader
	GetPayload() []byte
}

var _ ValidatedJws = &validJws{}

// type deprecatedSignedJws struct {
// 	SignedPayload opaqueData          `json:"payload"`
// 	Protected     *protectedHeader    `json:"protected,omitempty"`
// 	Unprotected   *RegisterdJwsHeader `json:"header,omitempty"`
// 	Signature     opaqueData          `json:"signature,omitempty"`
// 	Signatures    []*jwsSignature     `json:"signatures,omitempty"`

// 	// pointers to the validated data
// 	validated *validJws `json:"-"`
// }

type validJws struct {
	Payload     []byte
	Protected   map[string]any
	Unprotected map[string]any
}

// type jwsSignature struct {
// 	Protected *protectedHeader    `json:"protected,omitempty"`
// 	Header    *RegisterdJwsHeader `json:"header,omitempty"`
// 	Signature opaqueData          `json:"signature"`
// }

func (jws *validJws) ProtectedHeader() Header {
	return &jwsHeaderReader{
		jws:       jws,
		protected: true,
	}
}

func (jws *validJws) UnprotectedHeader() Header {
	return &jwsHeaderReader{
		jws:       jws,
		protected: false,
	}
}

func (jws *validJws) GetPayload() []byte {
	return []byte(jws.Payload)
}
