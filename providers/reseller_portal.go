package providers

import (
	"bytes"
	"encoding/json"
	"log"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"

	"github.com/pusher/oauth2_proxy/pkg/apis/sessions"
	"github.com/pusher/oauth2_proxy/pkg/requests"
)

type ResellerPortalProvider struct {
	*ProviderData
}

func NewResellerPortalProvider(p *ProviderData) *ResellerPortalProvider {
	p.ProviderName = "Reseller Portal"
	if p.LoginURL.String() == "" {
		p.LoginURL = &url.URL{
            Scheme: "https",
			Host: "my.securepoint.de",
			Path: "/oauth2/authorize",
		}
	}
	if p.RedeemURL.String() == "" {
		p.RedeemURL = &url.URL{
            Scheme: "https",
			Host: "my.securepoint.de",
			Path: "/oauth2/access_token",
		}
	}
	if p.ProfileURL.String() == "" {
		p.ProfileURL = &url.URL{
            Scheme: "https",
			Host: "my.securepoint.de",
			Path: "/api/user",
		}
	}
	if p.ValidateURL.String() == "" {
		p.ValidateURL = p.ProfileURL
	}
	if p.Scope == "" {
		p.Scope = "basic"
	}
	return &ResellerPortalProvider{ProviderData: p}
}

func getResellerPortalHeader(access_token string) http.Header {
	header := make(http.Header)
	header.Set("Accept", "application/json")
	header.Set("Authorization", fmt.Sprintf("Bearer %s", access_token))
	return header
}

func (p *ResellerPortalProvider) GetEmailAddress(s *sessions.SessionState) (string, error) {

	if s.AccessToken == "" {
		return "", errors.New("missing access token")
	}
	req, err := http.NewRequest("GET", p.ProfileURL.String(), nil)
	if err != nil {
		return "", err
	}
	req.Header = getResellerPortalHeader(s.AccessToken)

    respJSON, err := requests.Request(req)
    if err != nil {
        return "", fmt.Errorf("Invalid response")
    }

    email, err := respJSON.Get("email").String()
    if err != nil {
        return "", fmt.Errorf("Response does not contained an email")
    }
	return email, nil
}

func (p *ResellerPortalProvider) ValidateSessionState(s *sessions.SessionState) bool {
	return validateToken(p, s.AccessToken, getResellerPortalHeader(s.AccessToken))
}

func (p *ResellerPortalProvider) Redeem(redirectURL, code string) (s *sessions.SessionState, err error) {

	if code == "" {
		err = errors.New("missing code")
		return
	}

	params := url.Values{}
	params.Add("redirect_uri", redirectURL)
	params.Add("client_id", p.ClientID)
	params.Add("client_secret", p.ClientSecret)
	params.Add("code", code)
	params.Add("grant_type", "authorization_code")
	if p.ProtectedResource != nil && p.ProtectedResource.String() != "" {
		params.Add("resource", p.ProtectedResource.String())
	}

	var req *http.Request
	req, err = http.NewRequest("POST", p.RedeemURL.String(), bytes.NewBufferString(params.Encode()))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	var resp *http.Response
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	var body []byte
	body, err = ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return
	}

	if resp.StatusCode != 200 {
		err = fmt.Errorf("got %d from %q %s", resp.StatusCode, p.RedeemURL.String(), body)
		return
	}

	var jsonResponse struct {
		AccessToken string `json:"access_token"`
		ExpiresIn    int64  `json:"expires_in"`
		RefreshToken string `json:"refresh_token"`
	}
	err = json.Unmarshal(body, &jsonResponse)
	if err == nil {
		s = &sessions.SessionState{
			AccessToken:    jsonResponse.AccessToken,
		    ExpiresOn:      time.Now().Add(time.Duration(jsonResponse.ExpiresIn) * time.Second).Truncate(time.Second),
		    RefreshToken:   jsonResponse.RefreshToken,
		}
		return
	}

    err = fmt.Errorf("no access token found %s", body)
	return
}

func (p *ResellerPortalProvider) RefreshSessionIfNeeded(s *sessions.SessionState) (bool, error) {
    if s == nil || s.ExpiresOn.After(time.Now()) || s.RefreshToken == "" {
		return false, nil
	}

	origExpiration := s.ExpiresOn

    err := p.redeemRefreshToken(s)
	if err != nil {
		return false, err
	}

	log.Printf("refreshed access token %s (expired on %s)", s, origExpiration)
	return true, nil
}

func (p *ResellerPortalProvider) redeemRefreshToken(s *sessions.SessionState) (err error) {

	params := url.Values{}
	params.Add("client_id", p.ClientID)
	params.Add("client_secret", p.ClientSecret)
	params.Add("refresh_token", s.RefreshToken)
	params.Add("grant_type", "refresh_token")
	var req *http.Request
	req, err = http.NewRequest("POST", p.RedeemURL.String(), bytes.NewBufferString(params.Encode()))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return
	}
	var body []byte
	body, err = ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return
	}

	if resp.StatusCode != 200 {
		err = fmt.Errorf("\n\ngot %d from %q %s\n\n", resp.StatusCode, p.RedeemURL.String(), body)
		return
	}

	var jsonResponse struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
		RefreshToken string `json:"refresh_token"`
	}

    err = json.Unmarshal(body, &jsonResponse)
	if err == nil {
		s.AccessToken = jsonResponse.AccessToken
		s.ExpiresOn = time.Now().Add(time.Duration(jsonResponse.ExpiresIn) * time.Second).Truncate(time.Second)
		s.RefreshToken = jsonResponse.RefreshToken
		return
	}
	return
}
