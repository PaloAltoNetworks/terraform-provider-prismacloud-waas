package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/hashicorp/terraform-plugin-log/tflog"
)

type Rule struct {
	AllowMalformedHTTPHeaderNames bool              `json:"allowMalformedHttpHeaderNames,omitempty"`
	ApplicationsSpec              []ApplicationSpec `json:"applicationsSpec,omitempty"`
	AutoProtectPorts              bool              `json:"autoProtectPorts"`
	Collections                   []CollectionKey   `json:"collections"`
	Disabled                      bool              `json:"disabled,omitempty"`
	Modified                      time.Time         `json:"modified"`
	Name                          string            `json:"name"`
	Notes                         string            `json:"notes,omitempty"`
	Owner                         string            `json:"owner"`
	OutOfBandScope                string            `json:"outOfBandScope"`
	PreviousName                  string            `json:"previousName"`
	ReadTimeoutSeconds            int               `json:"readTimeoutSeconds"`
	SkipAPILearning               bool              `json:"skipAPILearning"`
	TrafficMirroring              TrafficMirroring  `json:"trafficMirroring"`
	Windows                       bool              `json:"windows"`
}

func (r Rule) Version() string {
	b, _ := json.Marshal(r)
	bv := sha256.Sum256(b)
	return fmt.Sprintf("sha256:%s", hex.EncodeToString(bv[:]))
}

type RuleVersion struct {
	Rule    `json:"rule"`
	Version string `json:"apiVersion"`
}

func newRuleVersion(r Rule) RuleVersion {
	return RuleVersion{
		Rule:    r,
		Version: r.Version(),
	}
}

type TrafficMirroring struct {
	Enabled bool `json:"enabled"`
}

type CreateRuleRequest struct {
	PolicyType `json:"policyType"`
	Rule       `json:"rule"`
}

func (c *Client) CreateRule(ctx context.Context, req CreateRuleRequest) (RuleVersion, error) {
	if err := req.PolicyType.Validate(); err != nil {
		return RuleVersion{}, err
	}
	if req.Name == "" {
		return RuleVersion{}, fmt.Errorf("%w: name", MissingRequiredValue)
	}
	p, err := c.GetPolicy(ctx, GetPolicyRequest{req.PolicyType})
	if err != nil {
		return RuleVersion{}, err
	}
	_, err = p.CreateRuleVersion(req.Rule)
	if err != nil {
		return RuleVersion{}, err
	}

	b, err := json.MarshalIndent(req.Rule, "", "\t")
	if err != nil {
		return RuleVersion{}, err
	}

	tflog.Debug(ctx, fmt.Sprintf("%s", b))

	pv, err := c.UpdatePolicy(ctx, UpdatePolicyRequest{req.PolicyType, p})
	if err != nil {
		return RuleVersion{}, err
	}
	return pv.GetRuleVersion(req.Name)
}

type ListRulesRequest struct {
	PolicyType `json:"PolicyType"`
}

func (c *Client) ListRules(ctx context.Context, req ListRulesRequest) ([]RuleVersion, error) {
	if err := req.PolicyType.Validate(); err != nil {
		return nil, err
	}
	p, err := c.GetPolicy(ctx, GetPolicyRequest{req.PolicyType})
	if err != nil {
		return nil, err
	}
	rvs := make([]RuleVersion, 0, len(p.Rules))
	for _, r := range p.Rules {
		rvs = append(rvs, newRuleVersion(r))
	}
	return rvs, nil
}

type GetRuleRequest struct {
	Name       string `json:"name"`
	PolicyType `json:"policyType"`
}

func (c *Client) GetRule(ctx context.Context, req GetRuleRequest) (RuleVersion, error) {
	if err := req.PolicyType.Validate(); err != nil {
		return RuleVersion{}, err
	}
	if req.Name == "" {
		return RuleVersion{}, fmt.Errorf("%w: name", MissingRequiredValue)
	}
	p, err := c.GetPolicy(ctx, GetPolicyRequest{req.PolicyType})
	if err != nil {
		return RuleVersion{}, err
	}
	return p.GetRuleVersion(req.Name)
}

type UpdateRuleRequest struct {
	PolicyType  `json:"policyType"`
	RuleVersion `json:"ruleVersion"`
}

func (c *Client) UpdateRule(ctx context.Context, req UpdateRuleRequest) (RuleVersion, error) {
	if req.Name == "" {
		return RuleVersion{}, fmt.Errorf("%w: name", MissingRequiredValue)
	}
	p, err := c.GetPolicy(ctx, GetPolicyRequest{req.PolicyType})
	if err != nil {
		return RuleVersion{}, err
	}
	_, err = p.UpdateRuleVersion(req.RuleVersion)
	if err != nil {
		return RuleVersion{}, err
	}

	pv, err := c.UpdatePolicy(ctx, UpdatePolicyRequest{req.PolicyType, p})
	if err != nil {
		return RuleVersion{}, err
	}
	return pv.GetRuleVersion(req.Name)
}

type DeleteRuleRequest struct {
	PolicyType `json:"policyType"`
	Name       string `json:"name"`
	Version    string `json:"apiVersion"`
}

type DeleteRuleResponse struct{}

func (c *Client) DeleteRule(ctx context.Context, req DeleteRuleRequest) (DeleteRuleResponse, error) {
	p, err := c.GetPolicy(ctx, GetPolicyRequest{req.PolicyType})
	if err != nil {
		return DeleteRuleResponse{}, err
	}
	err = p.DeleteRuleVersion(DeleteRuleRequest{
		PolicyType: req.PolicyType,
		Name:       req.Name,
		Version:    req.Version,
	})
	if err != nil {
		return DeleteRuleResponse{}, err
	}
	_, err = c.UpdatePolicy(ctx, UpdatePolicyRequest{req.PolicyType, p})
	return DeleteRuleResponse{}, err
}

type CollectionKey struct {
	Name string `json:"name"`
}
