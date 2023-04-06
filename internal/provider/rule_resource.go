package provider

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/PaloAltoNetworks/terraform-provider-prismacloud-waas/internal/api"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// Ensure provider defined types fully satisfy framework interfaces
var _ resource.Resource = &Rule{}
var _ resource.ResourceWithImportState = &Rule{}

func NewRule() resource.Resource {
	return &Rule{}
}

// Rule defines the resource implementation.
type Rule struct {
	client RuleClient
}

type RuleClient interface {
	CreateRule(ctx context.Context, req api.CreateRuleRequest) (api.RuleVersion, error)
	GetRule(ctx context.Context, req api.GetRuleRequest) (api.RuleVersion, error)
	UpdateRule(ctx context.Context, req api.UpdateRuleRequest) (api.RuleVersion, error)
	DeleteRule(ctx context.Context, req api.DeleteRuleRequest) (api.DeleteRuleResponse, error)
}

// RuleModel describes a WAAS Rule as a Terraform Resource.
type RuleModel struct {
	AllowMalformedHTTPHeaderNames types.Bool             `tfsdk:"allow_malformed_http_header_names"`
	ApplicationsSpec              types.List             `tfsdk:"applications_spec"`
	AutoProtectPorts              types.Bool             `tfsdk:"auto_protect_ports"`
	Collections                   types.Set              `tfsdk:"collections"`
	Disabled                      types.Bool             `tfsdk:"disabled"`
	Modified                      types.String           `tfsdk:"modified"`
	Name                          types.String           `tfsdk:"name"`
	Notes                         types.String           `tfsdk:"notes"`
	OutOfBandScope                types.String           `tfsdk:"out_of_band_scope"`
	Owner                         types.String           `tfsdk:"owner"`
	PreviousName                  types.String           `tfsdk:"previous_name"`
	PolicyType                    types.String           `tfsdk:"policy_type"`
	ReadTimeoutSeconds            types.Int64            `tfsdk:"read_timeout_seconds"`
	SkipAPILearning               types.Bool             `tfsdk:"skip_api_learning"`
	TrafficMirroring              *TrafficMirroringModel `tfsdk:"traffic_mirroring"`
	Version                       types.String           `tfsdk:"version"`
	Windows                       types.Bool             `tfsdk:"windows"`
}

func (r *RuleModel) Schema(_ context.Context) schema.Schema {
	var applicationSpecModel ApplicationSpecModel
	var collectionKeyModel CollectionKeyModel
	var trafficMirroringModel TrafficMirroringModel
	return schema.Schema{
		MarkdownDescription: "Rules defining a WAAS policy",
		Attributes: map[string]schema.Attribute{
			"allow_malformed_http_header_names": schema.BoolAttribute{
				Computed:            true,
				Default:             booldefault.StaticBool(false),
				MarkdownDescription: "Indicates if validation of http request header names should allow non-compliant characters",
				Optional:            true,
			},
			"applications_spec": schema.ListNestedAttribute{
				MarkdownDescription: applicationSpecModel.Schema().MarkdownDescription,
				NestedObject:        schema.NestedAttributeObject{Attributes: applicationSpecModel.Schema().Attributes},
				Optional:            true,
			},
			"auto_protect_ports": schema.BoolAttribute{
				Computed:            true,
				Default:             booldefault.StaticBool(true),
				MarkdownDescription: "Indicates if http ports should be automatically detected and protected",
				Optional:            true,
			},
			"collections": schema.SetNestedAttribute{
				MarkdownDescription: collectionKeyModel.Schema().MarkdownDescription,
				NestedObject:        schema.NestedAttributeObject{Attributes: collectionKeyModel.Schema().Attributes},
				Required:            true,
			},
			"disabled": schema.BoolAttribute{
				Computed:            true,
				Default:             booldefault.StaticBool(false),
				MarkdownDescription: "Indicates if the rule is currently disabled (true) or not (false)",
				Optional:            true,
			},
			"modified": schema.StringAttribute{
				MarkdownDescription: "Datetime when the rule was last modified",
				Computed:            true,
			},
			"name": schema.StringAttribute{
				MarkdownDescription: "Name of the rule",
				Required:            true,
			},
			"notes": schema.StringAttribute{
				Computed:            true,
				Default:             stringdefault.StaticString(""),
				MarkdownDescription: "Free-form text",
				Optional:            true,
			},
			"out_of_band_scope": schema.StringAttribute{
				MarkdownDescription: "Represents the Out-of-Band Rule Scope",
				Optional:            true,
				Validators: []validator.String{
					stringvalidator.OneOf(
						"", "container", "host",
					),
				},
			},
			"owner": schema.StringAttribute{
				MarkdownDescription: "User who created or last modified the rule",
				Computed:            true,
			},
			"policy_type": schema.StringAttribute{
				MarkdownDescription: "Type of policy to which the rule belongs",
				Required:            true,
				Validators: []validator.String{
					stringvalidator.OneOf(
						"agentlessAppFirewall", "appEmbeddedAppFirewall",
						"containerAppFirewall", "hostAppFirewall",
						"outOfBandAppFirewall", "serverlessAppFirewall",
					),
				},
			},
			"previous_name": schema.StringAttribute{
				Computed:            true,
				Default:             stringdefault.StaticString(""),
				MarkdownDescription: "Previous name of the rule. Required for rule renaming. This property is not stored in db, since it's used only to indicate rule renaming when new policy is received from client",
				Optional:            true,
			},
			"read_timeout_seconds": schema.Int64Attribute{
				Computed:            true,
				Default:             int64default.StaticInt64(5),
				MarkdownDescription: "ReadTimeout is the timeout of request reads in seconds, when no value is specified (0) the timeout is 5 seconds",
				Optional:            true,
			},
			"skip_api_learning": schema.BoolAttribute{
				Computed:            true,
				Default:             booldefault.StaticBool(false),
				MarkdownDescription: "SkipAPILearning indicates if API discovery is to be skipped (true) or not (false)",
				Optional:            true,
			},
			"traffic_mirroring": schema.SingleNestedAttribute{
				MarkdownDescription: trafficMirroringModel.Schema().MarkdownDescription,
				Attributes:          trafficMirroringModel.Schema().Attributes,
				Optional:            true,
			},
			"version": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Version is the unique fingerprint of a Rule definition, a matching version is required for an update",
				Optional:            true,
			},
			"windows": schema.BoolAttribute{
				Computed:            true,
				Default:             booldefault.StaticBool(false),
				MarkdownDescription: "Indicates whether the operating system of the app is windows, default is Linux",
				Optional:            true,
			},
		},
	}
}

func (r *Rule) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_rule"
}

func (r *Rule) Schema(ctx context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	var ruleModel RuleModel
	resp.Schema = ruleModel.Schema(ctx)
}

func (r *Rule) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	client, ok := req.ProviderData.(RuleClient)
	if !ok {
		resp.Diagnostics.AddError("Unexpected Resource Configure Type",
			fmt.Sprintf("Expected RuleClient, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)
		return
	}
	r.client = client
}

func (r *Rule) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan *RuleModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	createReq := api.CreateRuleRequest{
		PolicyType: api.PolicyType(plan.PolicyType.ValueString()),
		Rule: api.Rule{
			AllowMalformedHTTPHeaderNames: plan.AllowMalformedHTTPHeaderNames.ValueBool(),
			ApplicationsSpec: func() []api.ApplicationSpec {
				slice := make([]ApplicationSpecModel, 0, len(plan.ApplicationsSpec.Elements()))
				resp.Diagnostics.Append(plan.ApplicationsSpec.ElementsAs(ctx, &slice, false)...)
				applicationSpecs := make([]api.ApplicationSpec, 0, len(slice))
				for _, s := range slice {
					as, d := s.ToAPI(ctx)
					resp.Diagnostics.Append(d...)
					applicationSpecs = append(applicationSpecs, as.ApplicationSpec)
				}
				return applicationSpecs
			}(),
			AutoProtectPorts: plan.AutoProtectPorts.ValueBool(),
			Collections: func() []api.CollectionKey {
				slice := make([]CollectionKeyModel, 0, len(plan.Collections.Elements()))
				d := plan.Collections.ElementsAs(ctx, &slice, false)
				resp.Diagnostics.Append(d...)
				collections := make([]api.CollectionKey, 0, len(slice))
				for _, s := range slice {
					col := s.ToAPI()
					resp.Diagnostics.Append(d...)
					collections = append(collections, col)
				}
				return collections
			}(),
			Disabled:           plan.Disabled.ValueBool(),
			Name:               plan.Name.ValueString(),
			Notes:              plan.Notes.ValueString(),
			ReadTimeoutSeconds: int(plan.ReadTimeoutSeconds.ValueInt64()),
			SkipAPILearning:    plan.SkipAPILearning.ValueBool(),
			TrafficMirroring:   api.TrafficMirroring{Enabled: plan.TrafficMirroring != nil && plan.TrafficMirroring.Enabled.ValueBool()},
			Windows:            plan.Windows.ValueBool(),
		},
	}

	created, err := r.client.CreateRule(ctx, createReq)
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("unable to create Rule %q: %s", fmt.Sprintf("%s/%s", plan.PolicyType, plan.Name), err))
		return
	}
	tflog.Debug(ctx, fmt.Sprintf("created Rule resource %s/%s", createReq.PolicyType, createReq.Name))

	var ruleModel RuleModel
	createdState, diags := ruleModel.FromAPI(ctx, created)
	if diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}
	createdState.PolicyType = types.StringValue(plan.PolicyType.ValueString())

	// Save data into Terraform state
	resp.State.Schema = ruleModel.Schema(ctx)
	resp.Diagnostics.Append(resp.State.Set(ctx, &createdState)...)
}

func (r *Rule) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state RuleModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)

	tflog.Debug(ctx, fmt.Sprintf("read state: %+v", state))

	if resp.Diagnostics.HasError() {
		return
	}

	read, err := r.client.GetRule(ctx, api.GetRuleRequest{
		Name:       state.Name.ValueString(),
		PolicyType: api.PolicyType(state.PolicyType.ValueString()),
	})
	switch {
	case err == nil:
	case errors.Is(err, api.NotFound):
		// Recreate resource and return
		resp.State.RemoveResource(ctx)
		return
	default:
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("unable to read Rule %q: %s", fmt.Sprintf("%s/%s", state.PolicyType.ValueString(), state.Name.ValueString()), err))
		return
	}

	var m RuleModel
	m, diags := m.FromAPI(ctx, read)
	if diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}

	// Save updated data into Terraform state
	resp.State.Schema = m.Schema(ctx)
	m.PolicyType = state.PolicyType
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

func (r *Rule) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var state RuleModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)

	var plan RuleModel
	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	apiRuleVersion, diags := plan.ToAPI(ctx)
	if diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}
	update, err := r.client.UpdateRule(ctx, api.UpdateRuleRequest{
		PolicyType: api.PolicyType(plan.PolicyType.ValueString()),
		RuleVersion: api.RuleVersion{
			Rule:    apiRuleVersion.Rule,
			Version: state.Version.ValueString(),
		},
	})
	if err != nil {
		msg := fmt.Sprintf("unable to update Rule: %s", err)
		resp.Diagnostics.AddError("Client Error", msg)
		tflog.Error(ctx, msg)
		return
	}
	tflog.Debug(ctx, fmt.Sprintf("updated Rule resource %s/%s", state.PolicyType, state.Name))

	stateUpdate, diags := state.FromAPI(ctx, update)
	if diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}
	stateUpdate.PolicyType = plan.PolicyType
	stateUpdate.Name = plan.Name
	// Save updated data into Terraform state
	resp.State.Schema = state.Schema(ctx)
	resp.Diagnostics.Append(resp.State.Set(ctx, &stateUpdate)...)
}

func (r *Rule) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state *RuleModel
	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Read version from state
	var stateVersion string
	resp.Diagnostics.Append(req.State.GetAttribute(ctx, path.Root("version"), &stateVersion)...)
	var policyType string
	resp.Diagnostics.Append(req.State.GetAttribute(ctx, path.Root("policy_type"), &policyType)...)

	_, err := r.client.DeleteRule(ctx, api.DeleteRuleRequest{
		PolicyType: api.PolicyType(policyType),
		Name:       state.Name.ValueString(),
		Version:    stateVersion},
	)
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Unable to delete Rule %q: %s", fmt.Sprintf("%s/%s", policyType, state.Name.ValueString()), err.Error()))
		return
	}
	tflog.Debug(ctx, fmt.Sprintf("deleted Rule resource %s/%s", state.PolicyType, state.Name))
}

func (r *Rule) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	idParts := strings.Split(req.ID, "/")

	if len(idParts) != 2 || idParts[0] == "" || idParts[1] == "" {
		resp.Diagnostics.AddError(
			"Unexpected Rule Import Identifier",
			fmt.Sprintf("Expected import identifier with format: `<policy_type>/<rule_name>` Got: %q", req.ID),
		)
		return
	}
	policyType := idParts[0]
	name := idParts[1]

	rv, err := r.client.GetRule(ctx, api.GetRuleRequest{
		Name:       name,
		PolicyType: api.PolicyType(policyType),
	})
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Unable to get Rule with %q: %s", fmt.Sprintf("%s/%s", policyType, name), err.Error()))
		return
	}
	tflog.Debug(ctx, fmt.Sprintf("imported Rule resource %s/%s", policyType, name))

	var state RuleModel
	state, diags := state.FromAPI(ctx, rv)
	if diags.HasError() {
		return
	}
	state.PolicyType = types.StringValue(policyType)
	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
}

type TrafficMirroringModel struct {
	Enabled types.Bool `tfsdk:"enabled"`
}

func (t *TrafficMirroringModel) ToAPI() api.TrafficMirroring {
	return api.TrafficMirroring{
		Enabled: t.Enabled.ValueBool(),
	}
}

func (*TrafficMirroringModel) Schema() schema.Schema {
	return schema.Schema{
		MarkdownDescription: "TrafficMirroring is the traffic mirroring configuration",
		Attributes: map[string]schema.Attribute{
			"enabled": schema.BoolAttribute{
				Computed:            true,
				Default:             booldefault.StaticBool(false),
				MarkdownDescription: "Enabled indicates if traffic mirroring is enabled",
				Optional:            true,
			},
		},
	}
}

func (*RuleModel) FromAPI(ctx context.Context, a api.RuleVersion) (RuleModel, diag.Diagnostics) {
	var diagnostics diag.Diagnostics

	return RuleModel{
		AllowMalformedHTTPHeaderNames: types.BoolValue(a.AllowMalformedHTTPHeaderNames),
		ApplicationsSpec: func() types.List {
			var applicationSpec ApplicationSpecModel
			applicationSpecs := make([]ApplicationSpecModel, 0, len(a.ApplicationsSpec))
			for _, as := range a.ApplicationsSpec {
				asv := api.ApplicationSpecVersion{
					ApplicationSpec: as,
					Version:         as.Version(),
				}
				as, d := applicationSpec.FromAPI(ctx, asv)
				as.RuleName = types.StringValue(a.Name)
				diagnostics.Append(d...)
				applicationSpecs = append(applicationSpecs, as)
			}
			applicationSpecList, d := types.ListValueFrom(ctx, applicationSpec.Schema().Type(), applicationSpecs)
			diagnostics.Append(d...)
			return applicationSpecList
		}(),
		AutoProtectPorts: types.BoolValue(a.AutoProtectPorts),
		Collections: func() types.Set {
			var collectionModel CollectionKeyModel
			collections := make([]CollectionKeyModel, 0, len(a.Collections))
			for _, c := range a.Collections {
				collections = append(collections, collectionModel.FromAPI(ctx, c))
			}
			collectionSet, d := types.SetValueFrom(ctx, collectionModel.Schema().Type(), collections)
			diagnostics.Append(d...)
			return collectionSet
		}(),
		Disabled:           types.BoolValue(a.Disabled),
		Modified:           types.StringValue(a.Modified.Format(time.RFC3339)),
		Name:               types.StringValue(a.Name),
		Notes:              types.StringValue(a.Notes),
		Owner:              types.StringValue(a.Owner),
		PreviousName:       types.StringValue(a.PreviousName),
		ReadTimeoutSeconds: types.Int64Value(int64(a.ReadTimeoutSeconds)),
		SkipAPILearning:    types.BoolValue(a.SkipAPILearning),
		TrafficMirroring: &TrafficMirroringModel{
			Enabled: types.BoolValue(a.TrafficMirroring.Enabled),
		},
		Version: types.StringValue(a.Version),
		Windows: types.BoolValue(a.Windows),
	}, diagnostics
}

func (r *RuleModel) ToAPI(ctx context.Context) (api.RuleVersion, diag.Diagnostics) {
	var diagnostics diag.Diagnostics
	return api.RuleVersion{
		Rule: api.Rule{
			AllowMalformedHTTPHeaderNames: r.AllowMalformedHTTPHeaderNames.ValueBool(),
			ApplicationsSpec: func() []api.ApplicationSpec {
				applicationSpecModels := make([]ApplicationSpecModel, 0, len(r.ApplicationsSpec.Elements()))
				d := r.ApplicationsSpec.ElementsAs(ctx, &applicationSpecModels, false)
				diagnostics.Append(d...)
				applicationSpecs := make([]api.ApplicationSpec, 0, len(applicationSpecModels))
				for _, applicationSpecModel := range applicationSpecModels {
					s, d := applicationSpecModel.ToAPI(ctx)
					diagnostics.Append(d...)
					applicationSpecs = append(applicationSpecs, s.ApplicationSpec)
				}
				return applicationSpecs
			}(),
			AutoProtectPorts: r.AutoProtectPorts.ValueBool(),
			Collections: func() []api.CollectionKey {
				collectionModels := make([]CollectionKeyModel, 0, len(r.Collections.Elements()))
				d := r.Collections.ElementsAs(ctx, &collectionModels, false)
				diagnostics.Append(d...)
				collections := make([]api.CollectionKey, 0, len(collectionModels))
				for _, collectionModel := range collectionModels {
					collections = append(collections, collectionModel.ToAPI())
				}
				return collections
			}(),
			Disabled:           r.Disabled.ValueBool(),
			Name:               r.Name.ValueString(),
			Notes:              r.Notes.ValueString(),
			Owner:              r.Owner.ValueString(),
			OutOfBandScope:     r.OutOfBandScope.ValueString(),
			ReadTimeoutSeconds: int(r.ReadTimeoutSeconds.ValueInt64()),
			SkipAPILearning:    r.SkipAPILearning.ValueBool(),
			TrafficMirroring:   r.TrafficMirroring.ToAPI(),
			Windows:            r.Windows.ValueBool(),
		},
		Version: r.Version.ValueString(),
	}, diagnostics
}

type CollectionKeyModel struct {
	Name types.String `tfsdk:"name"`
}

func (*CollectionKeyModel) Schema() schema.Schema {
	return schema.Schema{
		MarkdownDescription: "Key of collection defining Rule scope",
		Attributes: map[string]schema.Attribute{
			"name": schema.StringAttribute{
				MarkdownDescription: "Unique name of collection",
				Required:            true,
			},
		},
	}
}

func (*CollectionKeyModel) FromAPI(_ context.Context, a api.CollectionKey) CollectionKeyModel {
	return CollectionKeyModel{
		Name: types.StringValue(a.Name),
	}
}

func (c *CollectionKeyModel) ToAPI() api.CollectionKey {
	return api.CollectionKey{
		Name: c.Name.ValueString(),
	}
}
