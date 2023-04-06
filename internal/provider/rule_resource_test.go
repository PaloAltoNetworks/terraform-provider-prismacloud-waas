package provider

import (
	"context"
	"testing"
	"time"

	"github.com/PaloAltoNetworks/terraform-provider-prismacloud-waas/internal/api"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestRule_Metadata(t *testing.T) {
	var rule Rule
	var metadata resource.MetadataResponse
	rule.Metadata(context.Background(), resource.MetadataRequest{}, &metadata)
	assert.Equal(t, "_rule", metadata.TypeName)
}

func TestRule_Schema(t *testing.T) {
	var rule Rule
	var schema resource.SchemaResponse
	rule.Schema(context.Background(), resource.SchemaRequest{}, &schema)
	assert.Empty(t, schema.Diagnostics)
	assert.Empty(t, schema.Schema.Validate())
	// shallow check, ensures no unexpected added attributes
	assert.Equal(t, 17, len(schema.Schema.Attributes))
}

func TestRule_Configure(t *testing.T) {
	var rule Rule
	ctx := context.Background()
	var config resource.ConfigureResponse
	rule.Configure(ctx, resource.ConfigureRequest{
		ProviderData: &mockRuleClient{},
	}, &config)
	assert.Empty(t, config.Diagnostics)
}

func TestRule_Create(t *testing.T) {
	ctx := context.Background()
	var rule Rule
	var schemaResponse resource.SchemaResponse
	rule.Schema(ctx, resource.SchemaRequest{}, &schemaResponse)
	if schemaResponse.Diagnostics.HasError() {
		t.Fatalf("%+v", schemaResponse.Diagnostics)
	}
	plan := tfsdk.Plan{Schema: schemaResponse.Schema}
	planRule := newRuleModel(t, ctx)
	diags := plan.Set(context.Background(), planRule)
	if diags.HasError() {
		t.Fatalf("%+v", diags)
	}

	var m mockRuleClient
	defer m.AssertExpectations(t)
	call := m.On(
		"CreateRule",
		mock.MatchedBy(func(r api.CreateRuleRequest) bool {
			expected := newCreateRuleRequest(t, r.Rule)
			return assert.Equal(t, expected, r)
		}),
	)
	call.RunFn = func(args mock.Arguments) {
		createRequest := args.Get(0).(api.CreateRuleRequest)
		expected := newCreateRuleRequest(t, createRequest.Rule)
		r := expected.Rule
		r.Owner = "owner"
		r.Modified = func() time.Time {
			modified, err := time.Parse(time.RFC3339, "2019-08-24T14:15:22Z")
			if err != nil {
				t.Fatal(err)
			}
			return modified
		}()
		rv := api.RuleVersion{
			Rule:    r,
			Version: r.Version(),
		}
		call.Return(rv, nil)
	}

	c := &Rule{client: &m}
	var resp resource.CreateResponse
	c.Create(ctx, resource.CreateRequest{Plan: plan}, &resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("%+v", resp.Diagnostics)
	}
	var created RuleModel
	diags = resp.State.Get(ctx, &created)
	if diags.HasError() {
		t.Fatalf("%+v", diags)
	}
	assert.Empty(t, planRule.Version)
	planRule.Version = created.Version
	assert.Equal(t, planRule, created)
}

func TestRule_Read(t *testing.T) {
	ctx := context.Background()
	var rule Rule
	var schemaResponse resource.SchemaResponse
	rule.Schema(ctx, resource.SchemaRequest{}, &schemaResponse)
	if schemaResponse.Diagnostics.HasError() {
		t.Fatalf("%+v", schemaResponse.Diagnostics)
	}
	state := tfsdk.State{Schema: schemaResponse.Schema}
	stateRule := newRuleModel(t, ctx)
	diags := state.Set(context.Background(), stateRule)
	if diags.HasError() {
		t.Fatalf("%+v", diags)
	}

	t.Run("read_success", func(t *testing.T) {
		var m mockRuleClient
		defer m.AssertExpectations(t)
		apiRule := newAPIRule(t)
		rv := api.RuleVersion{
			Rule:    apiRule,
			Version: apiRule.Version(),
		}
		m.On("GetRule", api.GetRuleRequest{
			Name:       "rule name",
			PolicyType: "container",
		}).Return(rv, nil)

		c := &Rule{client: &m}
		var resp resource.ReadResponse
		c.Read(ctx, resource.ReadRequest{State: state}, &resp)
		if resp.Diagnostics.HasError() {
			t.Fatalf("%+v", resp.Diagnostics)
		}
		var rm RuleModel
		diags = resp.State.Get(ctx, &rm)
		if diags.HasError() {
			t.Fatalf("%+v", diags)
		}
		stateRule.Version = rm.Version
		assert.Equal(t, stateRule, rm)
	})

	t.Run("read_not_found", func(t *testing.T) {
		var m mockRuleClient
		defer m.AssertExpectations(t)
		m.On("GetRule", api.GetRuleRequest{
			Name:       "rule name",
			PolicyType: "container",
		}).Return(api.RuleVersion{}, api.NotFound)

		c := &Rule{client: &m}
		resp := resource.ReadResponse{State: state}
		c.Read(ctx, resource.ReadRequest{State: state}, &resp)
		if resp.Diagnostics.HasError() {
			t.Fatalf("%+v", resp.Diagnostics)
		}
		assert.True(t, resp.State.Raw.IsNull())
	})

}

func TestRule_Update(t *testing.T) {
	existingRule := newAPIRule(t)
	existingVersion := existingRule.Version()

	ctx := context.Background()
	var rule Rule
	var schemaResponse resource.SchemaResponse
	rule.Schema(ctx, resource.SchemaRequest{}, &schemaResponse)
	if schemaResponse.Diagnostics.HasError() {
		t.Fatalf("%+v", schemaResponse.Diagnostics)
	}
	state := tfsdk.State{Schema: schemaResponse.Schema}
	stateRule := newRuleModel(t, ctx)
	stateRule.Version = types.StringValue(existingVersion)
	diags := state.Set(context.Background(), stateRule)
	if diags.HasError() {
		t.Fatalf("%+v", diags)
	}

	plan := tfsdk.Plan{Schema: schemaResponse.Schema}
	planRule := newRuleModel(t, ctx)
	planRule.Version = types.StringValue(existingVersion)
	planRule.Disabled = types.BoolValue(true)
	diags = plan.Set(context.Background(), planRule)
	if diags.HasError() {
		t.Fatalf("%+v", diags)
	}

	var m mockRuleClient
	defer m.AssertExpectations(t)

	call := m.On(
		"UpdateRule",
		mock.MatchedBy(func(r api.UpdateRuleRequest) bool {
			updateRuleRequest := api.UpdateRuleRequest{
				PolicyType: "container",
				RuleVersion: api.RuleVersion{
					Rule:    r.Rule,
					Version: existingVersion,
				},
			}
			return assert.Equal(t, updateRuleRequest, r)
		}),
	)
	call.RunFn = func(args mock.Arguments) {
		req := args.Get(0).(api.UpdateRuleRequest)
		expected := newUpdateRuleRequest(t, req.RuleVersion)
		r := expected.Rule
		// computed
		r.Owner = "owner"
		r.Modified = func() time.Time {
			modified, err := time.Parse(time.RFC3339, "2019-08-24T14:15:22Z")
			if err != nil {
				t.Fatal(err)
			}
			return modified
		}()
		// updated
		r.Disabled = true
		rv := api.RuleVersion{
			Rule:    r,
			Version: r.Version(),
		}
		call.Return(rv, nil)
	}

	c := &Rule{client: &m}
	var resp resource.UpdateResponse
	c.Update(ctx, resource.UpdateRequest{State: state, Plan: plan}, &resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("%+v", resp.Diagnostics)
	}
	var updated RuleModel
	diags = resp.State.Get(ctx, &updated)
	if diags.HasError() {
		t.Fatalf("%+v", diags)
	}
	planRule.Disabled = types.BoolValue(true)
	planRule.Version = updated.Version
	assert.Equal(t, planRule, updated)
}

func TestRule_Delete(t *testing.T) {
	deleteRule := newAPIRule(t)
	version := deleteRule.Version()

	var rule Rule
	var schemaResponse resource.SchemaResponse
	ctx := context.Background()
	rule.Schema(ctx, resource.SchemaRequest{}, &schemaResponse)
	if schemaResponse.Diagnostics.HasError() {
		t.Fatalf("%+v", schemaResponse.Diagnostics)
	}

	state := tfsdk.State{Schema: schemaResponse.Schema}
	stateRule := newRuleModel(t, ctx, func(rm *RuleModel) {
		rm.Version = types.StringValue(version)
	})
	diags := state.Set(context.Background(), stateRule)
	if diags.HasError() {
		t.Fatalf("%+v", diags)
	}

	var m mockRuleClient
	defer m.AssertExpectations(t)
	m.On(
		"DeleteRule",
		api.DeleteRuleRequest{
			PolicyType: "container",
			Name:       "rule name",
			Version:    version,
		},
	).Return(api.DeleteRuleResponse{}, nil)

	c := &Rule{client: &m}
	var resp resource.DeleteResponse
	c.Delete(ctx, resource.DeleteRequest{
		State: state,
	}, &resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("%+v", resp.Diagnostics)
	}
	assert.Empty(t, resp.State)
}

func TestRule_ImportState(t *testing.T) {
	var m mockRuleClient
	defer m.AssertExpectations(t)
	existing := newAPIRule(t)
	version := existing.Version()
	m.On(
		"GetRule",
		api.GetRuleRequest{
			PolicyType: "container",
			Name:       "rule name",
		},
	).Return(api.RuleVersion{
		Rule:    existing,
		Version: version,
	}, nil)

	c := &Rule{client: &m}
	var rule Rule
	var schemaResponse resource.SchemaResponse
	ctx := context.Background()
	rule.Schema(ctx, resource.SchemaRequest{}, &schemaResponse)
	if schemaResponse.Diagnostics.HasError() {
		t.Fatalf("%+v", schemaResponse.Diagnostics)
	}
	state := tfsdk.State{Schema: schemaResponse.Schema}
	resp := resource.ImportStateResponse{
		State: state,
	}
	c.ImportState(ctx, resource.ImportStateRequest{ID: "container/rule name"}, &resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("%+v", resp.Diagnostics)
	}

	expected := newRuleModel(t, ctx, func(rm *RuleModel) {
		rm.Version = types.StringValue(version)
	})
	var stateRule RuleModel
	diags := resp.State.Get(ctx, &stateRule)
	if diags.HasError() {
		t.Fatalf("%+v", diags)
	}
	assert.Equal(t, expected, stateRule)
}

var _ RuleClient = &mockRuleClient{}

type mockRuleClient struct {
	mock.Mock
}

func (m *mockRuleClient) CreateRule(_ context.Context, req api.CreateRuleRequest) (api.RuleVersion, error) {
	args := m.Called(req)
	resp := args.Get(0).(api.RuleVersion)
	return resp, args.Error(1)
}

func (m *mockRuleClient) GetRule(_ context.Context, req api.GetRuleRequest) (api.RuleVersion, error) {
	args := m.Called(req)
	resp := args.Get(0).(api.RuleVersion)
	return resp, args.Error(1)
}

func (m *mockRuleClient) UpdateRule(_ context.Context, req api.UpdateRuleRequest) (api.RuleVersion, error) {
	args := m.Called(req)
	resp := args.Get(0).(api.RuleVersion)
	return resp, args.Error(1)
}

func (m *mockRuleClient) DeleteRule(_ context.Context, req api.DeleteRuleRequest) (api.DeleteRuleResponse, error) {
	args := m.Called(req)
	resp := args.Get(0).(api.DeleteRuleResponse)
	return resp, args.Error(1)
}

func newCreateRuleRequest(t *testing.T, r api.Rule) api.CreateRuleRequest {
	t.Helper()
	return api.CreateRuleRequest{
		PolicyType: "container",
		Rule:       r,
	}
}

func newUpdateRuleRequest(t *testing.T, r api.RuleVersion) api.UpdateRuleRequest {
	t.Helper()
	return api.UpdateRuleRequest{
		PolicyType:  "container",
		RuleVersion: r,
	}
}

func newAPIRule(t *testing.T) api.Rule {
	t.Helper()
	return api.Rule{
		AllowMalformedHTTPHeaderNames: false,
		ApplicationsSpec:              []api.ApplicationSpec{newAPIApplicationSpec(t)},
		AutoProtectPorts:              true,
		Collections:                   []api.CollectionKey{{"collection"}},
		Disabled:                      false,
		Modified: func() time.Time {
			modified, err := time.Parse(time.RFC3339, "2019-08-24T14:15:22Z")
			if err != nil {
				t.Fatal(err)
			}
			return modified
		}(),
		Name:               "rule name",
		Notes:              "notes",
		Owner:              "owner",
		OutOfBandScope:     "",
		PreviousName:       "",
		ReadTimeoutSeconds: 5,
		SkipAPILearning:    false,
		TrafficMirroring:   api.TrafficMirroring{Enabled: false},
		Windows:            false,
	}
}

func newRuleModel(t *testing.T, ctx context.Context, options ...func(*RuleModel)) RuleModel {
	t.Helper()
	var diagnostics diag.Diagnostics
	rm := RuleModel{
		AllowMalformedHTTPHeaderNames: types.BoolValue(false),
		ApplicationsSpec: func() types.List {
			var applicationSpec ApplicationSpecModel
			list, diags := types.ListValueFrom(ctx, applicationSpec.Schema().Type(), []ApplicationSpecModel{
				newApplicationSpecModelVersion(t, ctx),
			})
			if diags.HasError() {
				t.Fatal(diags.Errors())
			}
			return list
		}(),
		AutoProtectPorts: types.BoolValue(true),
		Collections: func() types.Set {
			var collectionKeyModel CollectionKeyModel
			s, d := types.SetValueFrom(ctx, collectionKeyModel.Schema().Type(), []CollectionKeyModel{{Name: types.StringValue("collection")}})
			diagnostics.Append(d...)
			return s
		}(),
		Disabled: types.BoolValue(false),
		Modified: types.StringValue("2019-08-24T14:15:22Z"),
		Name:     types.StringValue("rule name"),
		Notes:    types.StringValue("notes"),
		// OutOfBandScope:     types.StringValue(""),
		Owner:              types.StringValue("owner"),
		PreviousName:       types.StringValue(""),
		PolicyType:         types.StringValue("container"),
		ReadTimeoutSeconds: types.Int64Value(5),
		SkipAPILearning:    types.BoolValue(false),
		TrafficMirroring:   &TrafficMirroringModel{Enabled: types.BoolValue(false)},
		// Version:            types.StringValue(""),
		Windows: types.BoolValue(false),
	}
	for _, option := range options {
		option(&rm)
	}
	return rm
}

func newApplicationSpecModelVersion(t *testing.T, ctx context.Context) ApplicationSpecModel {
	as := newAPIApplicationSpec(t)
	asv := api.ApplicationSpecVersion{
		ApplicationSpec: as,
		Version:         as.Version(),
	}
	var asm ApplicationSpecModel
	m, d := asm.FromAPI(ctx, asv)
	if d.HasError() {
		t.Fatalf("%+v", d)
	}
	return m
}
