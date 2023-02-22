package jwk

import (
	"context"
	"errors"
	"net/http"
)

var (
	ErrJkuBadScheme = errors.New("url must use https scheme")
)

type Client struct {
	client *http.Client
}

func FromJku(ctx context.Context, jku string) (JWKS, error) {
	panic("inimplemented")
	//return fetchJku(ctx, http.DefaultClient, jku)
}

func (c *Client) FromJku(ctx context.Context, jku string) (JWKS, error) {
	panic("inimplemented")
	//return fetchJku(ctx, c.client, jku)

}

// func fetchJku(ctx context.Context, cli *http.Client, url string) (JWKS, error) {

// 	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)

// 	// remotes must be https
// 	if req.URL.Scheme != "https" {
// 		return nil, ErrJkuBadScheme
// 	}

// 	resp, err := cli.Do(req)

// 	if err != nil {
// 		return nil, fmt.Errorf("unable to fetch jwks from given url %s: %w", url, err)
// 	}
// 	if resp.StatusCode != http.StatusOK {
// 		return nil, fmt.Errorf("bad response code from remote: %s", resp.Status)
// 	}

// 	keySet := &jwkSet{}
// 	if err = json.NewDecoder(resp.Body).Decode(keySet); err != nil {
// 		return nil, fmt.Errorf("bad response body json: %w", err)
// 	}

// 	return keySet.Keys, nil

// }
