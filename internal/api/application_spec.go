package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand"
	"strings"
	"time"
)

type ApplicationSpec struct {
	APISpec                   APISpec                   `json:"apiSpec"`
	AppID                     string                    `json:"appID"`
	AttackTools               ProtectionConfig          `json:"attackTools"`
	AutoApplyPatchesSpec      AutoApplyPatchesSpec      `json:"autoApplyPatchesSpec"`
	BanDurationMinutes        int                       `json:"banDurationMinutes,omitempty"`
	Body                      BodyConfig                `json:"body"`
	BotProtectionSpec         BotProtectionSpec         `json:"botProtectionSpec"`
	Certificate               Secret                    `json:"certificate,omitempty"`
	CMDi                      ProtectionConfig          `json:"cmdi"`
	ClickjackingEnabled       bool                      `json:"clickjackingEnabled"`
	CodeInjection             ProtectionConfig          `json:"codeInjection"`
	CSRFEnabled               bool                      `json:"csrfEnabled"`
	CustomBlockResponseConfig CustomBlockResponseConfig `json:"customBlockResponse"`
	CustomRules               []CustomRule              `json:"customRules,omitempty"`
	DisableEventIDHeader      bool                      `json:"disableEventIDHeader,omitempty"`
	DoSConfig                 DoSConfig                 `json:"dosConfig"`
	HeaderSpecs               []HeaderSpec              `json:"headerSpecs,omitempty"`
	IntelGathering            IntelGathering            `json:"intelGathering"`
	LFI                       ProtectionConfig          `json:"lfi"`
	MalformedReq              ProtectionConfig          `json:"malformedReq"`
	MaliciousUpload           MaliciousUpload           `json:"maliciousUpload"`
	NetworkControls           NetworkControls           `json:"networkControls"`
	RemoteHostForwarding      RemoteHostForwarding      `json:"remoteHostForwarding"`
	ResponseHeaderSpecs       []ResponseHeaderSpec      `json:"responseHeaderSpecs,omitempty"`
	RuleName                  string                    `json:"ruleName"`
	SessionCookieBan          bool                      `json:"sessionCookieBan,omitempty"`
	SessionCookieEnabled      bool                      `json:"sessionCookieEnabled,omitempty"`
	SessionCookieSameSite     string                    `json:"sessionCookieSameSite,omitempty"`
	SessionCookieSecure       bool                      `json:"sessionCookieSecure,omitempty"`
	Shellshock                ProtectionConfig          `json:"shellshock"`
	SQLi                      ProtectionConfig          `json:"sqli"`
	TLSConfig                 *TLSConfig                `json:"tlsConfig,omitempty"`
	XSS                       ProtectionConfig          `json:"xss"`
}

type CustomBlockResponseConfig struct {
	Body    string `json:"body,omitempty"`
	Code    int    `json:"code,omitempty"`
	Enabled bool   `json:"enabled,omitempty"`
}

type Secret struct {
	Encrypted string `json:"encrypted,omitempty"`
	Plain     string `json:"plain,omitempty"`
}

type TLSConfig struct {
	HSTSConfig    HSTSConfig       `json:"HSTSConfig"`
	Metadata      *CertificateMeta `json:"metadata"`
	MinTLSVersion string           `json:"minTLSVersion"`
}

func (t *TLSConfig) IsZero() bool {
	if *t == (TLSConfig{}) {
		return true
	}
	if t.Metadata == nil || *t.Metadata == (CertificateMeta{
		NotAfter: time.Time{},
	}) {
		return true
	}
	return false
}

type CertificateMeta struct {
	NotAfter    time.Time `json:"notAfter"`
	IssuerName  string    `json:"issuerName"`
	SubjectName string    `json:"subjectName"`
}

type HSTSConfig struct {
	Enabled           bool `json:"enabled"`
	MaxAgeSeconds     int  `json:"maxAgeSeconds"`
	IncludeSubdomains bool `json:"includeSubdomains"`
	Preload           bool `json:"preload"`
}

type Effect string

const (
	EffectAlert     Effect = "alert"
	EffectAllow     Effect = "allow"
	EffectBan       Effect = "ban"
	EffectDisable   Effect = "disable"
	EffectPrevent   Effect = "prevent"
	EffectReCAPTCHA Effect = "reCAPTCHA"
)

var validEffects = []Effect{EffectAlert, EffectAllow, EffectBan, EffectDisable, EffectPrevent, EffectReCAPTCHA}

func (e Effect) Validate() error {
	for _, effect := range validEffects {
		if e == effect {
			return nil
		}
	}
	return fmt.Errorf("%s is not a valid Effect", e)
}

func (e Effect) String() string {
	return string(e)
}

// ProtectionConfig all-purpose, generic protection configuration
type ProtectionConfig struct {
	Effect          Effect           `json:"effect"`
	ExceptionFields []ExceptionField `json:"exceptionFields"`
}

// ExceptionField TODO ExceptionLocation is an enum
type ExceptionField struct {
	Key      string `json:"key"`
	Location string `json:"location"`
}

// DoSConfig for Denial of Service attacks
type DoSConfig struct {
	AlertRates           DoSRates            `json:"alert"`
	BanRates             DoSRates            `json:"ban"`
	Enabled              bool                `json:"enabled"`
	ExcludedNetworkLists []string            `json:"excludedNetworkLists,omitempty"`
	MatchConditions      []DoSMatchCondition `json:"matchConditions,omitempty"`
	TrackSession         bool                `json:"trackSession,omitempty"`
}

type DoSRates struct {
	Average int `json:"average,omitempty"`
	Burst   int `json:"burst,omitempty"`
}

type DoSMatchCondition struct {
	FileTypes          []string          `json:"fileTypes,omitempty"`
	Methods            []string          `json:"methods,omitempty"`
	ResponseCodeRanges []StatusCodeRange `json:"responseCodeRanges,omitempty"`
}

type StatusCodeRange struct {
	End   int `json:"end,omitempty"`
	Start int `json:"start"`
}

// APISpec for endpoint level protections
type APISpec struct {
	Description              string     `json:"description,omitempty"`
	Effect                   Effect     `json:"effect"`
	Endpoints                []Endpoint `json:"endpoints,omitempty"`
	FallbackEffect           Effect     `json:"fallbackEffect"`
	Paths                    []Path     `json:"paths,omitempty"`
	QueryParamFallbackEffect Effect     `json:"queryParamFallbackEffect"`
}

type Endpoint struct {
	BasePath     string `json:"basePath"`
	ExposedPort  int    `json:"exposedPort"`
	GRPC         bool   `json:"grpc"`
	Host         string `json:"host"`
	HTTP2        bool   `json:"http2"`
	InternalPort int    `json:"internalPort"`
	TLS          bool   `json:"tls"`
}

type Path struct {
	Methods []Method `json:"methods,omitempty"`
	Name    string   `json:"path"`
}

type Method struct {
	Name       string  `json:"method"`
	Parameters []Param `json:"parameters,omitempty"`
}

// Param contains a parameter information.
// TODO the full-blown param spec constrains the Location, Type and Style with enums.
type Param struct {
	Array           bool     `json:"array,omitempty"`
	AllowEmptyValue bool     `json:"allowEmptyValue,omitempty"`
	Explode         bool     `json:"explode,omitempty"`
	Location        string   `json:"location"`
	Name            string   `json:"name"`
	Max             *float64 `json:"max,omitempty"`
	Min             *float64 `json:"min,omitempty"`
	Required        bool     `json:"required,omitempty"`
	Style           string   `json:"style,omitempty"`
	Type            string   `json:"type"`
}

// BotProtectionSpec is the bot protections spec
type BotProtectionSpec struct {
	InterstitialPage         bool                     `json:"interstitialPage"`
	JSInjectionSpec          JSInjectionSpec          `json:"jsInjectionSpec"`
	KnownBotProtectionsSpec  KnownBotProtectionsSpec  `json:"knownBotProtectionsSpec"`
	ReCAPTCHASpec            ReCAPTCHASpec            `json:"reCAPTCHASpec"`
	SessionValidation        Effect                   `json:"sessionValidation"`
	UnknownBotProtectionSpec UnknownBotProtectionSpec `json:"unknownBotProtectionSpec"`
	UserDefinedBots          []UserDefinedBot         `json:"userDefinedBots"`
}

type UserDefinedBot struct {
	Effect       Effect   `json:"effect"`
	HeaderName   string   `json:"headerName"`
	HeaderValues []string `json:"headerValues"`
	Name         string   `json:"name"`
	Subnets      []string `json:"subnets"`
}

type KnownBotProtectionsSpec struct {
	Archiving            Effect `json:"archiving"`
	BusinessAnalytics    Effect `json:"businessAnalytics"`
	CareerSearch         Effect `json:"careerSearch"`
	ContentFeedClients   Effect `json:"contentFeedClients"`
	Educational          Effect `json:"educational"`
	Financial            Effect `json:"financial"`
	MediaSearch          Effect `json:"mediaSearch" bson:"mediaSearch"`
	News                 Effect `json:"news"`
	SearchEngineCrawlers Effect `json:"searchEngineCrawlers"`
}

type UnknownBotProtectionSpec struct {
	APILibraries         Effect           `json:"apiLibraries" bson:"apiLibraries"`
	BotImpersonation     Effect           `json:"botImpersonation" bson:"botImpersonation"`
	BrowserImpersonation Effect           `json:"browserImpersonation" bson:"browserImpersonation"`
	Generic              Effect           `json:"generic" bson:"generic"`
	HTTPLibraries        Effect           `json:"httpLibraries" bson:"httpLibraries"`
	RequestAnomalies     RequestAnomalies `json:"requestAnomalies" bson:"requestAnomalies"`
	WebAutomationTools   Effect           `json:"webAutomationTools" bson:"webAutomationTools"`
	WebScrapers          Effect           `json:"webScrapers" bson:"webScrapers"`
}

// RequestAnomalies TODO RequestAnomalyThreshold is an enum with [3,6,9] as values
type RequestAnomalies struct {
	Effect    Effect `json:"effect"`
	Threshold int    `json:"threshold"`
}

type JSInjectionSpec struct {
	Enabled       bool   `json:"enabled"`
	TimeoutEffect Effect `json:"timeoutEffect"`
}

// ReCAPTCHASpec TODO ReCAPTCHAType is an enum
type ReCAPTCHASpec struct {
	AllSessions            bool   `json:"allSessions"`
	Enabled                bool   `json:"enabled"`
	SecretKey              Secret `json:"secretKey"`
	SiteKey                string `json:"siteKey"`
	SuccessExpirationHours int    `json:"successExpirationHours"`
	Type                   string `json:"type"`
}

// NetworkControls are enhancements to traditional WAF protections
type NetworkControls struct {
	AdvancedProtectionEffect Effect         `json:"advancedProtectionEffect"`
	CountriesAccess          AccessControls `json:"countries"`
	ExceptionSubnets         []string       `json:"exceptionSubnets,omitempty"`
	SubnetsAccess            AccessControls `json:"subnets"`
}

type AccessControls struct {
	Alert          []string `json:"alert,omitempty"`
	Allow          []string `json:"allow,omitempty"`
	AllowMode      bool     `json:"allowMode,omitempty"`
	Enabled        bool     `json:"enabled"`
	FallbackEffect Effect   `json:"fallbackEffect"`
	Prevent        []string `json:"prevent,omitempty"`
}

// BodyConfig allows for tuning of the Body read size and handling for oversize payloads
type BodyConfig struct {
	InspectionLimitExceededEffect Effect `json:"inspectionLimitExceededEffect"`
	InspectionSizeBytes           int    `json:"inspectionSizeBytes"`
	Skip                          bool   `json:"skip,omitempty"`
}

// HeaderSpec allows definition of header based protections
type HeaderSpec struct {
	Allow    bool     `json:"allow"`
	Effect   Effect   `json:"effect"`
	Name     string   `json:"name"`
	Required bool     `json:"required,omitempty"`
	Values   []string `json:"values"`
}

type IntelGathering struct {
	InfoLeakageEffect         Effect `json:"infoLeakageEffect"`
	RemoveFingerprintsEnabled bool   `json:"removeFingerprintsEnabled"`
}

// MaliciousUpload TODO FileType is an enum
type MaliciousUpload struct {
	AllowedExtensions []string `json:"allowedExtensions"`
	AllowedFileTypes  []string `json:"allowedFileTypes"`
	Effect            Effect   `json:"effect"`
}

type RemoteHostForwarding struct {
	Enabled bool   `json:"enabled,omitempty"`
	Target  string `json:"target,omitempty"`
}

// CustomRule TODO Action could be more strongly typed
type CustomRule struct {
	Action string `json:"action"`
	Effect Effect `json:"effect"`
	ID     int    `json:"_id"`
}

type AutoApplyPatchesSpec struct {
	Effect Effect `json:"effect"`
}

type ResponseHeaderSpec struct {
	Name     string   `json:"name"`
	Override bool     `json:"override"`
	Values   []string `json:"values"`
}

func (a *ApplicationSpec) Version() string {
	b, _ := json.Marshal(a)
	bv := sha256.Sum256(b)
	return fmt.Sprintf("sha256:%s", hex.EncodeToString(bv[:]))
}

type ApplicationSpecVersion struct {
	ApplicationSpec `json:"applicationSpec"`
	Version         string `json:"apiVersion"`
}

func newApplicationSpecVersion(a ApplicationSpec) ApplicationSpecVersion {
	return ApplicationSpecVersion{
		ApplicationSpec: a,
		Version:         a.Version(),
	}
}

// TODO This is the algorithm that PC uses to generate IDs - it can produce collisions
func generateAppID() string {
	chars := []rune("0123456789ABCDEF")
	charLen := len(chars)
	var sb strings.Builder
	sb.WriteString("app-")
	for i := 1; i <= 4; i++ {
		idx := rand.Intn(charLen)
		sb.WriteRune(chars[idx])
	}
	return sb.String()
}

type CreateApplicationSpecRequest struct {
	PolicyType      `json:"policyType"`
	ApplicationSpec `json:"applicationSpec"`
}

func (c *Client) CreateApplicationSpec(ctx context.Context, req CreateApplicationSpecRequest) (ApplicationSpecVersion, error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	p, err := c.getPolicy(ctx, GetPolicyRequest{req.PolicyType})
	if err != nil {
		return ApplicationSpecVersion{}, err
	}
	_, err = p.CreateApplicationSpecVersion(req.ApplicationSpec)
	if err != nil {
		return ApplicationSpecVersion{}, err
	}
	pv, err := c.updatePolicy(ctx, UpdatePolicyRequest{req.PolicyType, p})
	if err != nil {
		return ApplicationSpecVersion{}, err
	}
	return pv.GetApplicationSpecVersion(req.AppID)
}

type ListApplicationSpecsRequest struct {
	RuleName string
}

func (c *Client) ListApplicationSpecs(ctx context.Context, req ListApplicationSpecsRequest) (ListApplicationSpecsResponse, error) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	p, err := c.getPolicy(ctx, GetPolicyRequest{})
	if err != nil {
		return ListApplicationSpecsResponse{}, err
	}
	if err != nil {
		return ListApplicationSpecsResponse{}, err
	}
	rv, err := p.GetRuleVersion(req.RuleName)
	if err != nil {
		return ListApplicationSpecsResponse{}, err
	}
	return ListApplicationSpecsResponse{
		ApplicationSpecs: func() []ApplicationSpecVersion {
			asvs := make([]ApplicationSpecVersion, 0, len(rv.ApplicationsSpec))
			for _, a := range rv.ApplicationsSpec {
				asvs = append(asvs, newApplicationSpecVersion(a))
			}
			return asvs
		}(),
		RuleName: rv.Name,
	}, nil
}

type ListApplicationSpecsResponse struct {
	ApplicationSpecs []ApplicationSpecVersion
	RuleName         string
}

type GetApplicationSpecRequest struct {
	PolicyType `json:"policyType"`
	AppID      string `json:"appID"`
}

func (c *Client) GetApplicationSpec(ctx context.Context, req GetApplicationSpecRequest) (ApplicationSpecVersion, error) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	p, err := c.getPolicy(ctx, GetPolicyRequest{req.PolicyType})
	if err != nil {
		return ApplicationSpecVersion{}, err
	}
	return p.GetApplicationSpecVersion(req.AppID)
}

type UpdateApplicationSpecRequest struct {
	PolicyType             `json:"policyType"`
	ApplicationSpecVersion `json:"applicationSpecVersion"`
}

func (c *Client) UpdateApplicationSpec(ctx context.Context, req UpdateApplicationSpecRequest) (ApplicationSpecVersion, error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	p, err := c.getPolicy(ctx, GetPolicyRequest{req.PolicyType})
	if err != nil {
		return ApplicationSpecVersion{}, err
	}
	_, err = p.UpdateApplicationSpecVersion(req.ApplicationSpecVersion)
	if err != nil {
		return ApplicationSpecVersion{}, err
	}
	pv, err := c.updatePolicy(ctx, UpdatePolicyRequest{req.PolicyType, p})
	if err != nil {
		return ApplicationSpecVersion{}, err
	}
	return pv.GetApplicationSpecVersion(req.AppID)
}

type DeleteApplicationSpecRequest struct {
	PolicyType `json:"policyType"`
	AppID      string `json:"appID"`
	Version    string `json:"apiVersion"`
}

type DeleteApplicationSpecResponse struct{}

func (c *Client) DeleteApplicationSpec(ctx context.Context, req DeleteApplicationSpecRequest) (DeleteApplicationSpecResponse, error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	p, err := c.getPolicy(ctx, GetPolicyRequest{req.PolicyType})
	if err != nil {
		return DeleteApplicationSpecResponse{}, err
	}
	err = p.DeleteApplicationSpecVersion(DeleteApplicationSpecVersionRequest{
		AppID:   req.AppID,
		Version: req.Version,
	})
	if err != nil {
		return DeleteApplicationSpecResponse{}, err
	}
	_, err = c.updatePolicy(ctx, UpdatePolicyRequest{req.PolicyType, p})
	return DeleteApplicationSpecResponse{}, err
}
