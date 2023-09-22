package api

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/carlmjohnson/requests"
	"github.com/golang-jwt/jwt/v5"
)

type Config struct {
	ConsoleURL           string `json:"console_url"`
	APIVersion           string `json:"api_version"`
	Project              string `json:"project"`
	Username             string `json:"username"`
	Password             string `json:"password"`
	SkipCertVerification bool   `json:"skip_cert_verification"`
	SkipAuthentication   bool   `json:"skip_authentication"`
}

type Client struct {
	apiBuilder *requests.Builder
	apiVersion string
	mutex      sync.RWMutex
	token      string
}

func NewClient(config Config, c *http.Client) (*Client, error) {
	apiBuilder := requests.URL(config.ConsoleURL).
		Accept("application/json").
		Client(c)
	if config.Project != "" {
		apiBuilder.Param("project", config.Project)
	}
	client := Client{
		apiBuilder: apiBuilder,
		apiVersion: config.APIVersion,
	}
	if !config.SkipAuthentication {
		token, err := client.authenticate(context.Background(), config)
		if err != nil {
			return nil, err
		}
		client.token = token
		c.Transport = client.autorenew(nil)
		client.apiBuilder = client.apiBuilder.Bearer(token).Client(c)
	}
	return &client, nil
}

func (c *Client) authenticate(ctx context.Context, config Config) (string, error) {
	type authReq struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	var resp authResp
	err := requests.URL(fmt.Sprintf("%s/api/%s/authenticate", config.ConsoleURL, config.APIVersion)).
		BodyJSON(authReq{
			Username: config.Username,
			Password: config.Password,
		}).
		ToJSON(&resp).
		Fetch(ctx)
	return resp.Token, err
}

type authResp struct {
	Token string `json:"token"`
}

// Transport is an alias of http.RoundTripper for documentation purposes.
type Transport = http.RoundTripper

// RoundTripFunc is an adapter to use a function as an http.RoundTripper.
type RoundTripFunc func(req *http.Request) (res *http.Response, err error)

// RoundTrip implements http.RoundTripper.
func (rtf RoundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return rtf(r)
}

var _ Transport = RoundTripFunc(nil)

func (c *Client) autorenew(rt http.RoundTripper) Transport {
	if rt == nil {
		rt = http.DefaultTransport
	}
	return RoundTripFunc(func(req *http.Request) (*http.Response, error) {
		token, _, err := new(jwt.Parser).ParseUnverified(c.token, jwt.MapClaims{})
		if err != nil {
			return nil, err
		}
		exp, err := token.Claims.GetExpirationTime()
		if err != nil {
			return nil, err
		}
		if exp.Before(time.Now().Add(300 * time.Second)) {
			var renewal authResp
			err = c.apiBuilder.Clone().
				Pathf("api/%s/renew", c.apiVersion).
				ToJSON(&renewal).
				Fetch(context.Background())
			if err != nil {
				return nil, fmt.Errorf("unable to renew token")
			}
			c.token = renewal.Token
		}
		return rt.RoundTrip(req)
	})
}
