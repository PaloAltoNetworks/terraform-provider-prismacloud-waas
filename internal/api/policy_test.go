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

func TestClient_GetPolicy(t *testing.T) {
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
	}
	for _, test := range tests {
		t.Run(fmt.Sprintf("get_%s_policy", test.policyType), func(t *testing.T) {
			policy := newPolicy(t)
			policyVersion := newPolicyVersion(newPolicy(t))
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "GET", r.Method)
				assert.Equal(t, test.policyPath, r.URL.Path)
				b, err := json.Marshal(policy)
				require.NoError(t, err)
				_, _ = w.Write(b)
			}))
			defer s.Close()
			c := mustNewClient(t, s.URL)

			t.Run("get_policy_ok", func(t *testing.T) {
				p, err := c.GetPolicy(context.Background(), GetPolicyRequest{PolicyType: test.policyType})
				require.NoError(t, err)
				assert.Equal(t, policyVersion, p)
			})
		})
	}
}

func TestClient_UpdatePolicy(t *testing.T) {
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
	}
	for _, test := range tests {
		t.Run(fmt.Sprintf("update_%s_policy", test.policyType), func(t *testing.T) {
			policy := newPolicy(t, withPolicyType(test.policyType))
			policyVersion := newPolicyVersion(policy)
			updatedPolicy := newPolicy(t, withPolicyType(test.policyType), func(v *Policy) {
				v.MaxPort = 32000
			})
			updatedPolicyVersion := newPolicyVersion(updatedPolicy)
			t.Run("update_policy", func(t *testing.T) {
				updated := false
				s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					assert.Equal(t, test.policyPath, r.URL.Path)
					switch r.Method {
					case "GET":
						if !updated {
							b, err := json.Marshal(policy)
							require.NoError(t, err)
							_, _ = w.Write(b)
							return
						}
						b, err := json.Marshal(updatedPolicy)
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

				t.Run("update_policy_ok", func(t *testing.T) {
					p, err := c.UpdatePolicy(context.Background(), UpdatePolicyRequest{
						test.policyType,
						PolicyVersion{
							updatedPolicy,
							test.policyType,
							policyVersion.Version,
						}})
					require.NoError(t, err)
					assert.Equal(t, p, updatedPolicyVersion)
				})

				t.Run("update_version_conflict", func(t *testing.T) {
					updatedPolicy := newPolicy(t, withPolicyType(test.policyType), func(p *Policy) { p.MaxPort = 32000 })
					_, err := c.UpdatePolicy(context.Background(), UpdatePolicyRequest{
						test.policyType,
						PolicyVersion{Policy: updatedPolicy},
					})
					require.Error(t, err)
					assert.ErrorIs(t, err, VersionConflict{updatedPolicy.Version(), ""})
				})
			})
		})
	}
}
