package jwk

type JWKS struct {
	keys []*jwkAny `json:"keys"`
}

func (js *JWKS) GetKid(kid string) JWK {
	for i := range js.keys {
		if js.keys[i].KeyId == kid {
			//return js.keys[i]
		}
	}
	return nil
}

type jwkAny struct {
	KeyType    string   `json:"kty"`
	Use        string   `json:"use,omitempty"`
	KeyOptions []string `json:"key_ops,omitempty"`
	Algorithm  string   `json:"alg,omitempty"`
	KeyId      string   `json:"kid,omitempty"`
}

//var _ JWK = &jwkAny{}

func (j *jwkAny) Type() string {
	return j.KeyType
}
