package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/carlmjohnson/requests"
)

type Policy struct {
	ID      string `json:"_id"`
	MaxPort int    `json:"maxPort"`
	MinPort int    `json:"minPort"`
	Rules   []Rule `json:"rules"`
}

func (p *Policy) Version() string {
	b, _ := json.Marshal(p)
	bv := sha256.Sum256(b)
	return fmt.Sprintf("sha256:%s", hex.EncodeToString(bv[:]))
}

type PolicyVersion struct {
	Policy     `json:"policy"`
	PolicyType PolicyType `json:"policyType"`
	Version    string     `json:"apiVersion"`
}

func newPolicyVersion(p Policy) PolicyVersion {
	return PolicyVersion{
		Policy:  p,
		Version: p.Version(),
	}
}

type GetPolicyRequest struct {
	PolicyType PolicyType `json:"policyType"`
}

func (c *Client) GetPolicy(ctx context.Context, req GetPolicyRequest) (PolicyVersion, error) {
	builder, err := c.getPolicyEndpointBuilder(req.PolicyType)
	if err != nil {
		return PolicyVersion{}, err
	}
	var buf bytes.Buffer
	err = builder.ToBytesBuffer(&buf).Fetch(ctx)
	if err != nil {
		return PolicyVersion{}, err
	}
	var policy Policy
	if err = json.Unmarshal(buf.Bytes(), &policy); err != nil {
		return PolicyVersion{}, err
	}
	return PolicyVersion{
		Policy:  policy,
		Version: policy.Version(),
	}, nil
}

type UpdatePolicyRequest struct {
	PolicyType PolicyType `json:"policyType"`
	PolicyVersion
}

func (c *Client) UpdatePolicy(ctx context.Context, req UpdatePolicyRequest) (PolicyVersion, error) {
	currentPolicy, err := c.GetPolicy(ctx, GetPolicyRequest{req.PolicyType})
	if err != nil {
		return PolicyVersion{}, err
	}
	if currentPolicy.Version != req.Version {
		return PolicyVersion{}, VersionConflict{CurrentVersion: currentPolicy.Version, RequestVersion: req.Version}
	}
	builder, err := c.getPolicyEndpointBuilder(req.PolicyType)
	if err != nil {
		return PolicyVersion{}, err
	}
	err = builder.BodyJSON(req.Policy).Put().Fetch(ctx)
	if err != nil {
		return PolicyVersion{}, err
	}
	return c.GetPolicy(ctx, GetPolicyRequest{req.PolicyType})
}

func (p *Policy) CreateRuleVersion(r Rule) (RuleVersion, error) {
	_, err := p.findRuleVersionLocation(r.Name)
	switch {
	case err == nil:
		return RuleVersion{}, fmt.Errorf("%w: Rule with name=%s", ExistConflict, r.Name)
	case errors.Is(err, NotFound):
	default:
		return RuleVersion{}, err
	}
	p.Rules = append(p.Rules, r)
	return newRuleVersion(r), nil
}

func (p *Policy) GetRuleVersion(name string) (RuleVersion, error) {
	r, err := p.findRuleVersionLocation(name)
	if err != nil {
		return RuleVersion{}, err
	}
	return r.RuleVersion, nil
}

func (p *Policy) DeleteRuleVersion(spec DeleteRuleRequest) error {
	rl, err := p.findRuleVersionLocation(spec.Name)
	switch {
	case err == nil:
	case errors.Is(err, NotFound):
		return nil
	default:
		return err
	}
	if rl.Version != spec.Version {
		return VersionConflict{rl.Version, spec.Version}
	}
	p.Rules = append(
		p.Rules[:rl.RuleIndex],
		p.Rules[rl.RuleIndex+1:]...)
	return nil
}

func (p *Policy) UpdateRuleVersion(rv RuleVersion) (RuleVersion, error) {
	exist, err := p.findRuleVersionLocation(rv.Name)
	if err != nil {
		return RuleVersion{}, err
	}
	if exist.Version != rv.Version {
		return RuleVersion{}, VersionConflict{CurrentVersion: exist.Version, RequestVersion: rv.Version}
	}
	p.Rules[exist.RuleIndex] = rv.Rule
	return newRuleVersion(rv.Rule), nil
}

type ruleVersionLocation struct {
	RuleIndex int
	RuleVersion
}

func (p *Policy) findRuleVersionLocation(name string) (ruleVersionLocation, error) {
	for i, rule := range p.Rules {
		if rule.Name == name {
			return ruleVersionLocation{i, newRuleVersion(rule)}, nil
		}
	}
	return ruleVersionLocation{}, NotFound
}

func (p *Policy) GetApplicationSpecVersion(id string) (ApplicationSpecVersion, error) {
	asl, err := p.findApplicationSpecLocation(id)
	if err != nil {
		return ApplicationSpecVersion{}, err
	}
	return asl.ApplicationSpecVersion, nil
}

func (p *Policy) CreateApplicationSpecVersion(spec ApplicationSpec) (ApplicationSpecVersion, error) {
	if spec.RuleName == "" {
		return ApplicationSpecVersion{}, fmt.Errorf("%w: ruleName", MissingRequiredValue)

	}
	if spec.AppID != "" {
		_, err := p.findApplicationSpecLocation(spec.AppID)
		switch {
		case err == nil:
			return ApplicationSpecVersion{}, fmt.Errorf("%w: ApplicationSpec with appID=%s", ExistConflict, spec.AppID)
		case errors.Is(err, NotFound):
		default:
			return ApplicationSpecVersion{}, err
		}
	} else {
		spec.AppID = generateAppID()
	}
	rvl, err := p.findRuleVersionLocation(spec.RuleName)
	if err != nil {
		return ApplicationSpecVersion{}, err
	}
	p.Rules[rvl.RuleIndex].ApplicationsSpec = append(p.Rules[rvl.RuleIndex].ApplicationsSpec, spec)
	return newApplicationSpecVersion(spec), nil
}

func (p *Policy) UpdateApplicationSpecVersion(spec ApplicationSpecVersion) (ApplicationSpecVersion, error) {
	asl, err := p.findApplicationSpecLocation(spec.AppID)
	if err != nil {
		return ApplicationSpecVersion{}, err
	}
	if asl.Version != spec.Version {
		return ApplicationSpecVersion{}, VersionConflict{asl.Version, spec.Version}
	}
	p.Rules[asl.RuleIndex].ApplicationsSpec[asl.ApplicationSpecIndex] = spec.ApplicationSpec
	return newApplicationSpecVersion(spec.ApplicationSpec), nil
}

type DeleteApplicationSpecVersionRequest struct {
	AppID   string
	Version string
}

func (p *Policy) DeleteApplicationSpecVersion(spec DeleteApplicationSpecVersionRequest) error {
	asl, err := p.findApplicationSpecLocation(spec.AppID)
	switch {
	case err == nil:
	case errors.Is(err, NotFound):
		return nil
	default:
		return err
	}
	if asl.Version != spec.Version {
		return VersionConflict{asl.Version, spec.Version}
	}
	p.Rules[asl.RuleIndex].ApplicationsSpec = append(
		p.Rules[asl.RuleIndex].ApplicationsSpec[:asl.ApplicationSpecIndex],
		p.Rules[asl.RuleIndex].ApplicationsSpec[asl.ApplicationSpecIndex+1:]...)
	return nil
}

type ApplicationSpecLocation struct {
	RuleIndex            int
	ApplicationSpecIndex int
	ApplicationSpecVersion
}

func (p *Policy) findApplicationSpecLocation(id string) (ApplicationSpecLocation, error) {
	for i, rule := range p.Rules {
		for j, applicationSpec := range rule.ApplicationsSpec {
			if applicationSpec.AppID == id {
				applicationSpec.RuleName = rule.Name
				return ApplicationSpecLocation{i, j, newApplicationSpecVersion(applicationSpec)}, nil
			}
		}
	}
	return ApplicationSpecLocation{}, NotFound
}

const firewallPolicyPathFormat = "api/%s/policies/firewall/app/%s"

func (c *Client) getPolicyEndpointBuilder(policyType PolicyType) (*requests.Builder, error) {
	policyBuilder := func(policyPath string) *requests.Builder {
		return c.apiBuilder.Clone().Pathf(firewallPolicyPathFormat, c.apiVersion, policyPath)
	}
	switch policyType {
	case appEmbedded:
		return policyBuilder("app-embedded"), nil
	case container:
		return policyBuilder("container"), nil
	case host:
		return policyBuilder("host"), nil
	default:
		return nil, fmt.Errorf("unhandled policyType (%s)", policyType)
	}
}

type PolicyType string

const (
	agentless   PolicyType = "agentlessAppFirewall"
	appEmbedded PolicyType = "appEmbeddedAppFirewall"
	container   PolicyType = "containerAppFirewall"
	host        PolicyType = "hostAppFirewall"
	outOfBand   PolicyType = "outOfBandAppFirewall"
	serverless  PolicyType = "serverlessAppFirewall"
)

var ValidPolicyTypes = []PolicyType{agentless, appEmbedded, container, host, outOfBand, serverless}

func (p PolicyType) Validate() error {
	if p == "" {
		return fmt.Errorf("%w: policyType", MissingRequiredValue)
	}
	for _, v := range ValidPolicyTypes {
		if p == v {
			return nil
		}
	}
	return fmt.Errorf("%w: policyType(%q)", InvalidValue, p)
}
