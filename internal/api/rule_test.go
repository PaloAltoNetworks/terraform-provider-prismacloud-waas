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

func TestClient_CreateRule(t *testing.T) {
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
		t.Run(fmt.Sprintf("create_%s_rule", test.policyType), func(t *testing.T) {
			p := newPolicy(t, withPolicyType(test.policyType))
			r := newRule(t)
			up := newPolicy(t, withPolicyType(test.policyType), withRule(r))
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

			t.Run("with_name", func(t *testing.T) {
				rule, err := c.CreateRule(context.Background(), CreateRuleRequest{
					test.policyType,
					r,
				})
				require.NoError(t, err)
				assert.Equal(t, r, rule.Rule)
			})
			t.Run("no_name", func(t *testing.T) {
				_, err := c.CreateRule(context.Background(), CreateRuleRequest{
					test.policyType,
					Rule{},
				})
				require.Error(t, err)
				assert.ErrorIs(t, err, MissingRequiredValue)
			})
		})
	}
}

func TestClient_ListRules(t *testing.T) {
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
		t.Run(fmt.Sprintf("list_%s_rules", test.policyType), func(t *testing.T) {
			p := newPolicy(t, withPolicyType(test.policyType))
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, test.policyPath, r.URL.Path)
				assert.Equal(t, "GET", r.Method)
				b, err := json.Marshal(p)
				require.NoError(t, err)
				_, _ = w.Write(b)
			}))
			defer s.Close()

			c := mustNewClient(t, s.URL)

			t.Run("ok", func(t *testing.T) {
				require.True(t, len(p.Rules) > 0)
				require.Equal(t, "rule", p.Rules[0].Name)
				rules, err := c.ListRules(context.Background(), ListRulesRequest{test.policyType})
				require.NoError(t, err)
				assert.Equal(t, p.Rules[0], rules[0].Rule)
			})
		})
	}
}

func TestClient_GetRule(t *testing.T) {
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
		t.Run(fmt.Sprintf("get_%s_rule", test.policyType), func(t *testing.T) {
			p := newPolicy(t, withPolicyType(test.policyType))
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, test.policyPath, r.URL.Path)
				assert.Equal(t, "GET", r.Method)
				b, err := json.Marshal(p)
				require.NoError(t, err)
				_, _ = w.Write(b)
			}))
			defer s.Close()
			c := mustNewClient(t, s.URL)
			t.Run("with_name", func(t *testing.T) {
				require.True(t, len(p.Rules) > 0)
				require.Equal(t, "rule", p.Rules[0].Name)
				rule, err := c.GetRule(context.Background(), GetRuleRequest{
					"rule",
					test.policyType,
				})
				require.NoError(t, err)
				assert.Equal(t, p.Rules[0], rule.Rule)
			})
			t.Run("no_name", func(t *testing.T) {
				_, err := c.GetRule(context.Background(), GetRuleRequest{
					"",
					test.policyType,
				})
				require.Error(t, err)
				assert.ErrorIs(t, err, MissingRequiredValue)
			})
		})
	}
}

func TestClient_UpdateRule(t *testing.T) {
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
		t.Run(fmt.Sprintf("update_%s_rule", test.policyType), func(t *testing.T) {
			p := newPolicy(t, withPolicyType(test.policyType))
			r := newRule(t)
			r.Name = "rule"
			r.Windows = true
			up := newPolicy(t, withPolicyType(test.policyType))
			up.Rules[0] = r
			updated := false
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, test.policyPath, r.URL.Path)
				switch r.Method {
				case "PUT":
					updated = true
					w.WriteHeader(http.StatusOK)
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
				default:
					t.Errorf("unhandled method %s", r.Method)
				}
			}))
			defer s.Close()

			c := mustNewClient(t, s.URL)

			require.True(t, len(p.Rules) > 0)
			t.Run("ok", func(t *testing.T) {
				r, err := p.GetRuleVersion("rule")
				require.NoError(t, err)
				require.False(t, r.Windows)
				r.Windows = true
				rv, err := c.UpdateRule(context.Background(), UpdateRuleRequest{test.policyType, r})
				require.NoError(t, err)
				assert.True(t, rv.Windows)
				updated = false
			})
			t.Run("no_name", func(t *testing.T) {
				_, err := c.UpdateRule(context.Background(), UpdateRuleRequest{
					test.policyType,
					RuleVersion{},
				})
				require.Error(t, err)
				assert.ErrorIs(t, err, MissingRequiredValue)
			})
			t.Run("version_conflict", func(t *testing.T) {
				r, err := p.GetRuleVersion("rule")
				require.NoError(t, err)
				currentVersion := r.Version
				r.Version = ""
				_, err = c.UpdateRule(context.Background(), UpdateRuleRequest{test.policyType, r})
				require.Error(t, err)
				assert.ErrorIs(t, err, VersionConflict{CurrentVersion: currentVersion, RequestVersion: ""})
			})
		})
	}
}
