package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClient_CreateApplicationSpec(t *testing.T) {
	tests := []struct {
		policyType PolicyType
		policyPath string
	}{
		{
			container,
			"/api/vx.x/policies/firewall/app/container",
		},
		{
			host,
			"/api/vx.x/policies/firewall/app/host",
		},
		{
			appEmbedded,
			"/api/vx.x/policies/firewall/app/app-embedded",
		},
	}
	for _, test := range tests {
		t.Run(fmt.Sprintf("create_%s_application_spec", test.policyType), func(t *testing.T) {
			p := newPolicy(t, withPolicyType(test.policyType))
			as := newApplicationSpec(t, func(a *ApplicationSpec) { a.AppID = "new app" })
			up := newPolicy(t, withPolicyType(test.policyType), withApplicationSpec(as))
			updated := false
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, test.policyPath, r.URL.Path)
				switch r.Method {
				case "GET":
					if !updated {
						b, err := json.Marshal(p)
						require.NoError(t, err)
						_, _ = w.Write(b)
						return
					}
					b, err := json.Marshal(up)
					require.NoError(t, err)
					_, _ = w.Write(b)
					return
				case "PUT":
					updated = true
					w.WriteHeader(http.StatusOK)
					return
				default:
					t.Errorf("unhandled method %s", r.Method)
				}
			}))
			defer s.Close()

			c := mustNewClient(t, s.URL)
			t.Run("ok", func(t *testing.T) {
				a, err := c.CreateApplicationSpec(context.Background(), CreateApplicationSpecRequest{test.policyType, as})
				require.NoError(t, err)
				assert.Equal(t, as, a.ApplicationSpec)
			})

			t.Run("not_found", func(t *testing.T) {
				_, err := c.GetApplicationSpec(context.Background(), GetApplicationSpecRequest{test.policyType, "nonexistent"})
				require.Error(t, err)
				assert.ErrorIs(t, err, NotFound)
			})
		})
	}
}

func TestClient_GetApplicationSpec(t *testing.T) {
	tests := []struct {
		policyType  PolicyType
		expectedURL string
	}{
		{
			container,
			"/api/vx.x/policies/firewall/app/container",
		},
		{
			host,
			"/api/vx.x/policies/firewall/app/host",
		},
		{
			appEmbedded,
			"/api/vx.x/policies/firewall/app/app-embedded",
		},
	}
	for _, test := range tests {
		t.Run(fmt.Sprintf("get_%s_application_spec", test.policyType), func(t *testing.T) {
			p := newPolicy(t, withPolicyType(test.policyType))
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "GET", r.Method)
				assert.Equal(t, test.expectedURL, r.URL.Path)
				b, err := json.Marshal(p)
				require.NoError(t, err)
				_, _ = w.Write(b)
			}))
			defer s.Close()

			c := mustNewClient(t, s.URL)
			t.Run("ok", func(t *testing.T) {
				as := newApplicationSpec(t)
				a, err := c.GetApplicationSpec(context.Background(), GetApplicationSpecRequest{test.policyType, as.AppID})
				require.NoError(t, err)
				assert.Equal(t, as, a.ApplicationSpec)
			})

			t.Run("not_found", func(t *testing.T) {
				_, err := c.GetApplicationSpec(context.Background(), GetApplicationSpecRequest{test.policyType, "nonexistent"})
				require.Error(t, err)
				assert.ErrorIs(t, err, NotFound)
			})
		})
	}
}

func TestClient_UpdateApplicationSpec(t *testing.T) {
	tests := []struct {
		policyType PolicyType
		policyPath string
	}{
		{
			container,
			"/api/vx.x/policies/firewall/app/container",
		},
		{
			host,
			"/api/vx.x/policies/firewall/app/host",
		},
		{
			appEmbedded,
			"/api/vx.x/policies/firewall/app/app-embedded",
		},
	}
	for _, test := range tests {
		t.Run(fmt.Sprintf("update_%s_application_spec", test.policyType), func(t *testing.T) {
			p := newPolicy(t, withPolicyType(test.policyType))
			up := newPolicy(t, withPolicyType(test.policyType))
			updated := false
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, test.policyPath, r.URL.Path)
				switch r.Method {
				case "GET":
					if !updated {
						b, err := json.Marshal(p)
						require.NoError(t, err)
						_, _ = w.Write(b)
						return
					}
					b, err := json.Marshal(up)
					require.NoError(t, err)
					_, _ = w.Write(b)
					return
				case "PUT":
					updated = true
					w.WriteHeader(http.StatusOK)
					return
				default:
					t.Errorf("unhandled method %s", r.Method)
				}
			}))
			defer s.Close()

			c := mustNewClient(t, s.URL)
			t.Run("not_found", func(t *testing.T) {
				_, err := c.UpdateApplicationSpec(context.Background(), UpdateApplicationSpecRequest{
					test.policyType,
					ApplicationSpecVersion{ApplicationSpec: ApplicationSpec{AppID: "nonexistent"}}})
				require.Error(t, err)
				assert.ErrorIs(t, err, NotFound)
			})

			asv, err := up.GetApplicationSpecVersion("app-000A")
			require.NoError(t, err)
			require.Equal(t, true, asv.CSRFEnabled)
			asv.CSRFEnabled = false
			asvUpdated, err := up.UpdateApplicationSpecVersion(asv)
			require.NoError(t, err)

			t.Run("ok", func(t *testing.T) {
				a, err := c.UpdateApplicationSpec(context.Background(), UpdateApplicationSpecRequest{
					test.policyType,
					asv})
				require.NoError(t, err)
				assert.Equal(t, asv.ApplicationSpec, a.ApplicationSpec)
			})

			t.Run("version_conflict", func(t *testing.T) {
				_, err := c.UpdateApplicationSpec(context.Background(), UpdateApplicationSpecRequest{
					test.policyType,
					ApplicationSpecVersion{ApplicationSpec: asv.ApplicationSpec}})
				require.Error(t, err)
				assert.ErrorIs(t, err, VersionConflict{CurrentVersion: asvUpdated.Version, RequestVersion: ""})
			})
		})
	}
}

func TestClient_DeleteApplicationSpec(t *testing.T) {
	tests := []struct {
		policyType PolicyType
		policyPath string
	}{
		{
			container,
			"/api/vx.x/policies/firewall/app/container",
		},
		{
			host,
			"/api/vx.x/policies/firewall/app/host",
		},
		{
			appEmbedded,
			"/api/vx.x/policies/firewall/app/app-embedded",
		},
	}
	for _, test := range tests {
		t.Run(fmt.Sprintf("delete_%s_application_spec", test.policyType), func(t *testing.T) {
			p := newPolicy(t, withPolicyType(test.policyType))
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, test.policyPath, r.URL.Path)
				switch r.Method {
				case "GET":
					b, err := json.Marshal(p)
					require.NoError(t, err)
					_, _ = w.Write(b)
					return
				case "DELETE":
					w.WriteHeader(http.StatusOK)
					return
				case "PUT":
					w.WriteHeader(http.StatusOK)
					return
				default:
					t.Errorf("unhandled method %s", r.Method)
				}
			}))
			defer s.Close()

			c := mustNewClient(t, s.URL)
			asv, err := p.GetApplicationSpecVersion("app-000A")
			require.NoError(t, err)
			t.Run("not_found", func(t *testing.T) {
				_, err := c.DeleteApplicationSpec(context.Background(), DeleteApplicationSpecRequest{
					test.policyType,
					"nonexistent",
					asv.Version,
				})
				require.NoError(t, err)
			})

			t.Run("ok", func(t *testing.T) {
				_, err := c.DeleteApplicationSpec(context.Background(), DeleteApplicationSpecRequest{
					test.policyType,
					"app-000A",
					asv.Version,
				})
				require.NoError(t, err)
			})

			t.Run("version_conflict", func(t *testing.T) {
				_, err := c.DeleteApplicationSpec(context.Background(), DeleteApplicationSpecRequest{
					test.policyType,
					"app-000A",
					""})
				require.Error(t, err)
				assert.ErrorIs(t, err, VersionConflict{CurrentVersion: asv.Version, RequestVersion: ""})
			})
		})
	}
}
