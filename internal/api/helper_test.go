package api

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newPolicy(t *testing.T, options ...func(policy *Policy)) Policy {
	t.Helper()
	modified := mustParseTime(t, "2022-09-15T14:04:28.453Z")
	policy := Policy{
		ID:      "containerAppFirewall",
		MaxPort: 31000,
		MinPort: 30000,
		Rules: []Rule{
			{
				Collections: []CollectionKey{{
					Name: "policy",
				}},
				ApplicationsSpec:   []ApplicationSpec{newApplicationSpec(t)},
				ReadTimeoutSeconds: 0,
				Windows:            false, // TODO omitempty?
				SkipAPILearning:    false,
				AutoProtectPorts:   true,
				Modified:           modified,
				Owner:              "admin",
				Name:               "rule",
				PreviousName:       "",
				Disabled:           true,
			},
		},
	}
	for _, option := range options {
		option(&policy)
	}
	return policy
}

func withPolicyType(policyType PolicyType) func(p *Policy) {
	return func(p *Policy) {
		p.ID = string(policyType)
	}
}

func newRule(t *testing.T, options ...func(rule *Rule)) Rule {
	t.Helper()
	modified := mustParseTime(t, "2022-09-15T14:04:28.453Z")
	r := Rule{
		Collections: []CollectionKey{{
			Name: "policy",
		}},
		Modified: modified,
		Name:     "new rule",
	}
	for _, option := range options {
		option(&r)
	}
	return r
}

func withRule(rule Rule) func(p *Policy) {
	return func(p *Policy) {
		_, err := p.CreateRuleVersion(rule)
		if err != nil {
			panic(err)
		}
	}
}

func withApplicationSpec(spec ApplicationSpec) func(p *Policy) {
	return func(p *Policy) {
		_, err := p.CreateApplicationSpecVersion(spec)
		if err != nil {
			panic(err)
		}
	}
}

func newApplicationSpec(t *testing.T, options ...func(spec *ApplicationSpec)) ApplicationSpec {
	t.Helper()
	a := ApplicationSpec{
		AppID: "app-000A",
		// SessionCookieEnabled:  false,
		// SessionCookieBan:      false,
		SessionCookieSameSite: "Lax",
		// SessionCookieSecure:   false,
		BanDurationMinutes: 5,
		Certificate:        Secret{},
		DoSConfig:          DoSConfig{},
		APISpec: APISpec{
			Endpoints: []Endpoint{{
				Host:     "*",
				BasePath: "*",
			}},
			Effect:                   "disable",
			FallbackEffect:           "disable",
			QueryParamFallbackEffect: "disable",
		},
		BotProtectionSpec: BotProtectionSpec{
			UserDefinedBots: []UserDefinedBot{},
			KnownBotProtectionsSpec: KnownBotProtectionsSpec{
				SearchEngineCrawlers: "disable",
				BusinessAnalytics:    "disable",
				Educational:          "disable",
				News:                 "disable",
				Financial:            "disable",
				ContentFeedClients:   "disable",
				Archiving:            "disable",
				CareerSearch:         "disable",
				MediaSearch:          "disable",
			},
			UnknownBotProtectionSpec: UnknownBotProtectionSpec{
				Generic:              "disable",
				WebAutomationTools:   "disable",
				WebScrapers:          "disable",
				APILibraries:         "disable",
				HTTPLibraries:        "disable",
				BotImpersonation:     "disable",
				BrowserImpersonation: "disable",
				RequestAnomalies: RequestAnomalies{
					Threshold: 9,
					Effect:    "disable",
				},
			},
			SessionValidation: "disable",
			JSInjectionSpec: JSInjectionSpec{
				TimeoutEffect: "disable",
			},
			ReCAPTCHASpec: ReCAPTCHASpec{
				AllSessions:            true,
				Type:                   "checkbox",
				SuccessExpirationHours: 24,
			},
		},
		NetworkControls: NetworkControls{
			AdvancedProtectionEffect: "alert",
			SubnetsAccess: AccessControls{
				AllowMode:      true,
				FallbackEffect: "alert",
			},
			CountriesAccess: AccessControls{
				AllowMode:      true,
				FallbackEffect: "alert",
			},
		},
		Body: BodyConfig{
			InspectionSizeBytes:           131072,
			InspectionLimitExceededEffect: "disable",
		},
		IntelGathering: IntelGathering{
			InfoLeakageEffect:         "disable",
			RemoveFingerprintsEnabled: true,
		},
		MaliciousUpload: MaliciousUpload{
			Effect:            "disable",
			AllowedExtensions: []string{},
			AllowedFileTypes:  []string{},
		},
		CSRFEnabled: true,
		SQLi: ProtectionConfig{
			Effect:          "alert",
			ExceptionFields: []ExceptionField{},
		},
		XSS: ProtectionConfig{
			Effect:          "alert",
			ExceptionFields: []ExceptionField{},
		},
		AttackTools: ProtectionConfig{
			Effect:          "alert",
			ExceptionFields: []ExceptionField{},
		},
		Shellshock: ProtectionConfig{
			Effect:          "alert",
			ExceptionFields: []ExceptionField{},
		},
		MalformedReq: ProtectionConfig{
			Effect:          "alert",
			ExceptionFields: []ExceptionField{},
		},
		CMDi: ProtectionConfig{
			Effect:          "alert",
			ExceptionFields: []ExceptionField{},
		},
		LFI: ProtectionConfig{
			Effect:          "alert",
			ExceptionFields: []ExceptionField{},
		},
		CodeInjection: ProtectionConfig{
			Effect:          "alert",
			ExceptionFields: []ExceptionField{},
		},
		RemoteHostForwarding: RemoteHostForwarding{},
		CustomRules:          nil,
		// AutoApplyPatchesSpec: AutoApplyPatchesSpec{},
		DisableEventIDHeader: false,
		ResponseHeaderSpecs:  nil,
		RuleName:             "rule",
	}
	for _, option := range options {
		option(&a)
	}
	return a
}

func mustNewClient(t *testing.T, serverURL string) *Client {
	t.Helper()
	c, err := NewClient(Config{
		ConsoleURL:         serverURL,
		APIVersion:         "vx.x",
		SkipAuthentication: true,
	}, http.DefaultClient)
	assert.NoError(t, err)
	return c
}

func mustParseTime(t *testing.T, s string) time.Time {
	t.Helper()
	modified, err := time.Parse(time.RFC3339, s)
	require.NoError(t, err)
	return modified
}
