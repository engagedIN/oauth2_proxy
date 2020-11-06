package providers

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/coreos/go-oidc"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/requests"
)

var (
	// ErrNotImplemented is returned when a provider did not override a default
	// implementation method that doesn't have sensible defaults
	ErrNotImplemented = errors.New("not implemented")

	_ Provider = (*ProviderData)(nil)
)

// Redeem provides a default implementation of the OAuth2 token redemption process
func (p *ProviderData) Redeem(ctx context.Context, redirectURL, code string) (s *sessions.SessionState, err error) {
	if code == "" {
		err = errors.New("missing code")
		return
	}
	clientSecret, err := p.GetClientSecret()
	if err != nil {
		return
	}

	params := url.Values{}
	params.Add("redirect_uri", redirectURL)
	params.Add("client_id", p.ClientID)
	params.Add("client_secret", clientSecret)
	params.Add("code", code)
	params.Add("grant_type", "authorization_code")
	if p.ProtectedResource != nil && p.ProtectedResource.String() != "" {
		params.Add("resource", p.ProtectedResource.String())
	}

	result := requests.New(p.RedeemURL.String()).
		WithContext(ctx).
		WithMethod("POST").
		WithBody(bytes.NewBufferString(params.Encode())).
		SetHeader("Content-Type", "application/x-www-form-urlencoded").
		Do()
	if result.Error() != nil {
		return nil, result.Error()
	}

	// blindly try json and x-www-form-urlencoded
	var jsonResponse struct {
		AccessToken string `json:"access_token"`
	}
	err = result.UnmarshalInto(&jsonResponse)
	if err == nil {
		s = &sessions.SessionState{
			AccessToken: jsonResponse.AccessToken,
		}
		return
	}

	var v url.Values
	v, err = url.ParseQuery(string(result.Body()))
	if err != nil {
		return
	}
	if a := v.Get("access_token"); a != "" {
		created := time.Now()
		s = &sessions.SessionState{AccessToken: a, CreatedAt: &created}
	} else {
		err = fmt.Errorf("no access token found %s", result.Body())
	}
	return
}

// GetLoginURL with typical oauth parameters
func (p *ProviderData) GetLoginURL(redirectURI, state string) string {
	extraParams := url.Values{}
	a := makeLoginURL(p, redirectURI, state, extraParams)
	return a.String()
}

// GetEmailAddress returns the Account email address
// DEPRECATED: Migrate to EnrichSessionState
func (p *ProviderData) GetEmailAddress(_ context.Context, _ *sessions.SessionState) (string, error) {
	return "", ErrNotImplemented
}

// ValidateGroup validates that the provided email exists in the configured provider
// email group(s).
func (p *ProviderData) ValidateGroup(_ string) bool {
	return true
}

// EnrichSessionState is called after Redeem to allow providers to enrich session fields
// such as User, Email, Groups with provider specific API calls.
func (p *ProviderData) EnrichSessionState(_ context.Context, _ *sessions.SessionState) error {
	return nil
}

// ValidateSessionState validates the AccessToken
func (p *ProviderData) ValidateSessionState(ctx context.Context, s *sessions.SessionState) bool {
	return validateToken(ctx, p, s.AccessToken, nil)
}

// RefreshSessionIfNeeded should refresh the user's session if required and
// do nothing if a refresh is not required
func (p *ProviderData) RefreshSessionIfNeeded(_ context.Context, _ *sessions.SessionState) (bool, error) {
	return false, nil
}

// CreateSessionStateFromBearerToken should be implemented to allow providers
// to convert ID tokens into sessions
func (p *ProviderData) CreateSessionStateFromBearerToken(_ context.Context, _ string, _ *oidc.IDToken) (*sessions.SessionState, error) {
	return nil, ErrNotImplemented
}
