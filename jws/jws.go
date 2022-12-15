package jws

type JWS interface {
	JOSEHeader
	Payload() []byte

	JSONEncode() ([]byte, error)
	CompactEncode() (string, error)
	String() string
}

var _ JWS = &signedJws{}

type signedJws struct {
	SignedPayload opaqueData       `json:"payload"`
	Protected     *protectedHeader `json:"protected,omitempty"`
	Unprotected   *registerdHeader `json:"header,omitempty"`
	Signature     opaqueData       `json:"signature,omitempty"`
	Signatures    []*jwsSignature  `json:"signatures,omitempty"`

	// pointers to the validated data
	validated *validatedJws `json:"-"`
}

type validatedJws struct {
	Payload     *opaqueData
	Protected   *registerdHeader
	Unprotected *registerdHeader
}

type jwsSignature struct {
	Protected *protectedHeader `json:"protected,omitempty"`
	Header    *registerdHeader `json:"header,omitempty"`
	Signature opaqueData       `json:"signature"`
}

func (jws *signedJws) ProtectedHeader() Header {
	return &jwsHeaderReader{
		jws:       jws.validated,
		protected: true,
	}
}

func (jws *signedJws) UnprotectedHeader() Header {
	return &jwsHeaderReader{
		jws:       jws.validated,
		protected: false,
	}
}

func (jws *signedJws) Payload() []byte {
	return []byte(jws.SignedPayload)
}

//TODO: io.ReaderWriter interface?
