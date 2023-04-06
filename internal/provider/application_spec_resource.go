package provider

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/PaloAltoNetworks/terraform-provider-prismacloud-waas/internal/api"
	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/defaults"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/listdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// Ensure provider defined types fully satisfy framework interfaces
var _ resource.Resource = &ApplicationSpec{}
var _ resource.ResourceWithImportState = &ApplicationSpec{}

func NewApplicationSpec() resource.Resource {
	return &ApplicationSpec{}
}

// ApplicationSpec defines the resource implementation.
type ApplicationSpec struct {
	client ApplicationSpecClient
}

func (r *ApplicationSpec) Schema(_ context.Context, _ resource.SchemaRequest, response *resource.SchemaResponse) {
	var applicationSpecModel ApplicationSpecModel
	response.Schema = applicationSpecModel.Schema()
}

func (r *ApplicationSpec) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_application_spec"
}

func (r *ApplicationSpec) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	// Prevent panic if the provider has not been configured.
	if req.ProviderData == nil {
		return
	}
	client, ok := req.ProviderData.(ApplicationSpecClient)
	if !ok {
		resp.Diagnostics.AddError("Unexpected Resource Configure Type", fmt.Sprintf("Expected ApplicationSpecClient, got: %T. Please report this issue to the provider developers.", req.ProviderData))
		return
	}
	r.client = client
}

func (r *ApplicationSpec) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan ApplicationSpecModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)

	if resp.Diagnostics.HasError() {
		return
	}

	apiApplicationSpecVersion, diags := plan.ToAPI(ctx)
	if diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}
	var createReq = api.CreateApplicationSpecRequest{
		ApplicationSpec: apiApplicationSpecVersion.ApplicationSpec,
	}
	created, err := r.client.CreateApplicationSpec(ctx, createReq)
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("unable to create ApplicationSpec: %s", err))
		return
	}
	tflog.Trace(ctx, fmt.Sprintf("created ApplicationSpec resource AppID=%s", created.AppID))

	var applicationSpecModel ApplicationSpecModel
	createdState, diags := applicationSpecModel.FromAPI(ctx, created)
	if diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}

	// Save data into Terraform state
	resp.State.Schema = applicationSpecModel.Schema()
	resp.Diagnostics.Append(resp.State.Set(ctx, &createdState)...)
}

func (r *ApplicationSpec) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state ApplicationSpecModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)

	read, err := r.client.GetApplicationSpec(ctx, api.GetApplicationSpecRequest{AppID: state.AppID.ValueString()})
	switch {
	case err == nil:
	case errors.Is(err, api.NotFound):
		// Recreate resource and return
		resp.State.RemoveResource(ctx)
		return
	default:
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("unable to read ApplicationSpec: %s", err))
		return
	}

	var applicationSpecModel ApplicationSpecModel
	state, diags := applicationSpecModel.FromAPI(ctx, read)
	if diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}

	// Save updated data into Terraform state
	resp.State.Schema = applicationSpecModel.Schema()
	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
}

func (r *ApplicationSpec) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan ApplicationSpecModel
	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Read version from state
	var stateVersion string
	resp.Diagnostics.Append(req.State.GetAttribute(ctx, path.Root("version"), &stateVersion)...)

	apiApplicationSpecVersion, diags := plan.ToAPI(ctx)
	if diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}
	apiApplicationSpecVersion.Version = stateVersion

	update, err := r.client.UpdateApplicationSpec(ctx, api.UpdateApplicationSpecRequest{ApplicationSpecVersion: apiApplicationSpecVersion})
	if err != nil {
		msg := fmt.Sprintf("unable to update ApplicationSpec: %s", err)
		resp.Diagnostics.AddError("Client Error", msg)
		tflog.Error(ctx, msg)
		return
	}

	var state ApplicationSpecModel
	stateUpdate, diags := state.FromAPI(ctx, update)

	// Save updated data into Terraform state
	resp.State.Schema = state.Schema()
	resp.Diagnostics.Append(resp.State.Set(ctx, &stateUpdate)...)
}

func (r *ApplicationSpec) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state ApplicationSpecModel
	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	// Read version from state
	var stateVersion string
	resp.Diagnostics.Append(req.State.GetAttribute(ctx, path.Root("version"), &stateVersion)...)

	_, err := r.client.DeleteApplicationSpec(ctx, api.DeleteApplicationSpecRequest{AppID: state.AppID.ValueString(), Version: stateVersion})
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Unable to delete ApplicationSpec with AppID=%q: %s", state.AppID.ValueString(), err.Error()))
		return
	}
}

func (r *ApplicationSpec) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	read, err := r.client.GetApplicationSpec(ctx, api.GetApplicationSpecRequest{AppID: req.ID})
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("unable to read ApplicationSpec: %s", err))
		return
	}
	var applicationSpecModel ApplicationSpecModel
	state, diags := applicationSpecModel.FromAPI(ctx, read)
	if diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}
	// Save updated data into Terraform state
	resp.State.Schema = applicationSpecModel.Schema()
	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
}

type ApplicationSpecClient interface {
	CreateApplicationSpec(ctx context.Context, req api.CreateApplicationSpecRequest) (api.ApplicationSpecVersion, error)
	GetApplicationSpec(ctx context.Context, req api.GetApplicationSpecRequest) (api.ApplicationSpecVersion, error)
	ListApplicationSpecs(ctx context.Context, req api.ListApplicationSpecsRequest) (api.ListApplicationSpecsResponse, error)
	UpdateApplicationSpec(ctx context.Context, req api.UpdateApplicationSpecRequest) (api.ApplicationSpecVersion, error)
	DeleteApplicationSpec(ctx context.Context, req api.DeleteApplicationSpecRequest) (api.DeleteApplicationSpecResponse, error)
}

// ApplicationSpecModel describes the resource data model
type ApplicationSpecModel struct {
	APISpec                   APISpecModel                   `tfsdk:"api_spec"`
	AppID                     types.String                   `tfsdk:"app_id"`
	AttackTools               ProtectionConfigModel          `tfsdk:"attack_tools"`
	AutoApplyPatchesSpec      AutoApplyPatchesSpecModel      `tfsdk:"auto_apply_patches_spec"`
	BanDurationMinutes        types.Int64                    `tfsdk:"ban_duration_minutes"`
	Body                      BodyModel                      `tfsdk:"body"`
	BotProtectionSpec         BotProtectionSpecModel         `tfsdk:"bot_protection_spec"`
	Certificate               SecretModel                    `tfsdk:"certificate"`
	ClickjackingEnabled       types.Bool                     `tfsdk:"clickjacking_enabled"`
	CMDi                      ProtectionConfigModel          `tfsdk:"cmdi"`
	CodeInjection             ProtectionConfigModel          `tfsdk:"code_injection"`
	CSRFEnabled               types.Bool                     `tfsdk:"csrf_enabled"`
	CustomRules               types.List                     `tfsdk:"custom_rules"`
	CustomBlockResponseConfig CustomBlockResponseConfigModel `tfsdk:"custom_block_response_config"`
	DisableEventIDHeader      types.Bool                     `tfsdk:"disable_event_id_header"`
	DoSConfig                 DoSConfigModel                 `tfsdk:"dos_config"`
	HeaderSpecs               types.List                     `tfsdk:"header_specs"`
	IntelGathering            IntelGatheringModel            `tfsdk:"intel_gathering"`
	LFi                       ProtectionConfigModel          `tfsdk:"lfi"`
	MalformedReq              ProtectionConfigModel          `tfsdk:"malformed_req"`
	MaliciousUpload           MaliciousUploadModel           `tfsdk:"malicious_upload"`
	NetworkControls           NetworkControlsModel           `tfsdk:"network_controls"`
	RemoteHostForwarding      RemoteHostForwardingModel      `tfsdk:"remote_host_forwarding"`
	ResponseHeaderSpecs       types.List                     `tfsdk:"response_header_specs"`
	RuleName                  types.String                   `tfsdk:"rule_name"`
	SessionCookieBan          types.Bool                     `tfsdk:"session_cookie_ban"`
	SessionCookieEnabled      types.Bool                     `tfsdk:"session_cookie_enabled"`
	SessionCookieSameSite     types.String                   `tfsdk:"session_cookie_same_site"`
	SessionCookieSecure       types.Bool                     `tfsdk:"session_cookie_secure"`
	Shellshock                ProtectionConfigModel          `tfsdk:"shellshock"`
	SQLi                      ProtectionConfigModel          `tfsdk:"sqli"`
	TLSConfig                 *TLSConfigModel                `tfsdk:"tls_config"`
	Version                   types.String                   `tfsdk:"version"`
	XSS                       ProtectionConfigModel          `tfsdk:"xss"`
}

func (*ApplicationSpecModel) Schema() schema.Schema {
	var apiSpecModel APISpecModel
	var autoApplyProtectionSpecModel AutoApplyPatchesSpecModel
	var protectionConfigModel ProtectionConfigModel
	var bodyModel BodyModel
	var botProtectionSpecModel BotProtectionSpecModel
	var secretModel SecretModel
	var customBlockResponseConfigModel CustomBlockResponseConfigModel
	var customRuleModel CustomRuleModel
	var doSConfigModel DoSConfigModel
	var headerSpecModel HeaderSpecModel
	var intelGatheringModel IntelGatheringModel
	var maliciousUploadModel MaliciousUploadModel
	var networkControlsModel NetworkControlsModel
	var remoteHostForwardingModel RemoteHostForwardingModel
	var responseHeaderSpecsModel ResponseHeaderSpecsModel
	var tlsConfigModel TLSConfigModel
	return schema.Schema{
		MarkdownDescription: "Prisma Cloud Application Spec resource",
		Attributes: map[string]schema.Attribute{
			"api_spec": schema.SingleNestedAttribute{
				Attributes:          apiSpecModel.Schema().Attributes,
				MarkdownDescription: apiSpecModel.Schema().MarkdownDescription,
				Required:            true,
			},
			"app_id": schema.StringAttribute{
				MarkdownDescription: "Unique ID for the app",
				Optional:            true,
			},
			"attack_tools": schema.SingleNestedAttribute{
				Attributes:          protectionConfigModel.Schema().Attributes,
				MarkdownDescription: "Local File Inclusion protection configuration",
				Required:            true,
			},
			"auto_apply_patches_spec": schema.SingleNestedAttribute{
				Attributes:          autoApplyProtectionSpecModel.Schema().Attributes,
				MarkdownDescription: "Configuration for automatic application of virtual patches",
				Required:            true,
			},
			"ban_duration_minutes": schema.Int64Attribute{
				Computed:            true,
				Default:             int64default.StaticInt64(5),
				MarkdownDescription: "Ban duration, in minutes",
				Optional:            true,
			},
			"body": schema.SingleNestedAttribute{
				Attributes:          bodyModel.Schema().Attributes,
				MarkdownDescription: bodyModel.Schema().MarkdownDescription,
				Required:            true,
			},
			"bot_protection_spec": schema.SingleNestedAttribute{
				Attributes:          botProtectionSpecModel.Schema().Attributes,
				MarkdownDescription: botProtectionSpecModel.Schema().MarkdownDescription,
				Required:            true,
			},
			"certificate": schema.SingleNestedAttribute{
				Attributes:          secretModel.Schema().Attributes,
				MarkdownDescription: secretModel.Schema().MarkdownDescription,
				Optional:            true,
			},
			"clickjacking_enabled": schema.BoolAttribute{
				Computed:            true,
				Default:             booldefault.StaticBool(true),
				MarkdownDescription: "Indicates whether Clickjacking protection is enabled. When enabled, WAAS modifies all response headers, setting the X-Frame-Options response header value to SAMEORIGIN. The SAMEORIGIN directive only permits a page to be displayed in a frame on the same origin as the page itself.",
				Optional:            true,
			},
			"cmdi": schema.SingleNestedAttribute{
				Attributes:          protectionConfigModel.Schema().Attributes,
				MarkdownDescription: protectionConfigModel.Schema().MarkdownDescription,
				Required:            true,
			},
			"code_injection": schema.SingleNestedAttribute{
				Attributes:          protectionConfigModel.Schema().Attributes,
				MarkdownDescription: protectionConfigModel.Schema().MarkdownDescription,
				Required:            true,
			},
			"csrf_enabled": schema.BoolAttribute{
				MarkdownDescription: "Indicates whether Cross-Site Request Forgery (CSRF) protection is enabled",
				Required:            true,
			},
			"custom_rules": schema.ListNestedAttribute{
				NestedObject:        schema.NestedAttributeObject{Attributes: customRuleModel.Schema().Attributes},
				MarkdownDescription: "List of custom rules",
				Optional:            true,
			},
			"custom_block_response_config": schema.SingleNestedAttribute{
				Attributes:          customBlockResponseConfigModel.Schema().Attributes,
				MarkdownDescription: customBlockResponseConfigModel.Schema().MarkdownDescription,
				Required:            true,
			},
			"disable_event_id_header": schema.BoolAttribute{
				Computed:            true,
				Default:             booldefault.StaticBool(false),
				MarkdownDescription: "Indicates if event ID header should be attached to the response",
				Optional:            true,
			},
			"dos_config": schema.SingleNestedAttribute{
				MarkdownDescription: doSConfigModel.Schema().MarkdownDescription,
				Attributes:          doSConfigModel.Schema().Attributes,
				Required:            true,
			},
			"header_specs": schema.ListNestedAttribute{
				MarkdownDescription: "Configuration for inspecting HTTP headers",
				NestedObject:        schema.NestedAttributeObject{Attributes: headerSpecModel.Schema().Attributes},
				Required:            true,
			},
			"intel_gathering": schema.SingleNestedAttribute{
				Attributes:          intelGatheringModel.Schema().Attributes,
				MarkdownDescription: intelGatheringModel.Schema().MarkdownDescription,
				Required:            true,
			},
			"lfi": schema.SingleNestedAttribute{
				Attributes:          protectionConfigModel.Schema().Attributes,
				MarkdownDescription: "Local File Inclusion protection configuration",
				Required:            true,
			},
			"malformed_req": schema.SingleNestedAttribute{
				Attributes:          protectionConfigModel.Schema().Attributes,
				MarkdownDescription: "Malformed Request protection configuration",
				Required:            true,
			},
			"malicious_upload": schema.SingleNestedAttribute{
				Attributes:          maliciousUploadModel.Schema().Attributes,
				MarkdownDescription: maliciousUploadModel.Schema().MarkdownDescription,
				Required:            true,
			},
			"network_controls": schema.SingleNestedAttribute{
				Attributes:          networkControlsModel.Schema().Attributes,
				MarkdownDescription: networkControlsModel.Schema().MarkdownDescription,
				Required:            true,
			},
			"remote_host_forwarding": schema.SingleNestedAttribute{
				Attributes:          remoteHostForwardingModel.Schema().Attributes,
				MarkdownDescription: remoteHostForwardingModel.Schema().MarkdownDescription,
				Required:            true,
			},
			"response_header_specs": schema.ListNestedAttribute{
				MarkdownDescription: responseHeaderSpecsModel.Schema().MarkdownDescription,
				NestedObject:        schema.NestedAttributeObject{Attributes: responseHeaderSpecsModel.Schema().Attributes},
				Required:            true,
			},
			"rule_name": schema.StringAttribute{
				MarkdownDescription: "Name of Rule to which Application Spec belongs",
				Required:            true,
			},
			"session_cookie_ban": schema.BoolAttribute{
				Computed:            true,
				Default:             booldefault.StaticBool(false),
				MarkdownDescription: "Indicates if bans in this app are made by session cookie ID",
				Optional:            true,
			},
			"session_cookie_enabled": schema.BoolAttribute{
				Computed:            true,
				Default:             booldefault.StaticBool(false),
				MarkdownDescription: "Indicates if session cookies are enabled",
				Optional:            true,
			},
			"session_cookie_same_site": schema.StringAttribute{
				MarkdownDescription: "Indicates the SameSite attribute of the session cookie is set",
				Computed:            true,
				Default:             stringdefault.StaticString("Lax"),
				Optional:            true,
				Validators: []validator.String{
					stringvalidator.OneOf("Lax", "None", "Strict"),
				},
			},
			"session_cookie_secure": schema.BoolAttribute{
				Computed:            true,
				Default:             booldefault.StaticBool(false),
				MarkdownDescription: "Indicates the Secure attribute of the session cookie is set",
				Optional:            true,
			},
			"shellshock": schema.SingleNestedAttribute{
				Attributes: protectionConfigModel.Schema().Attributes,
				// Computed:            true,
				// Default:             protectionConfigDefault(),
				MarkdownDescription: protectionConfigModel.Schema().MarkdownDescription,
				// Optional:            true,
				Required: true,
			},
			"sqli": schema.SingleNestedAttribute{
				Attributes:          protectionConfigModel.Schema().Attributes,
				MarkdownDescription: protectionConfigModel.Schema().MarkdownDescription,
				Required:            true,
			},
			"tls_config": schema.SingleNestedAttribute{
				Attributes:          tlsConfigModel.Schema().Attributes,
				MarkdownDescription: tlsConfigModel.Schema().MarkdownDescription,
				Optional:            true,
			},
			"version": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "the unique fingerprint of the Application Definition, used for optimistic locking",
				Optional:            true,
			},
			"xss": schema.SingleNestedAttribute{
				Attributes:          protectionConfigModel.Schema().Attributes,
				MarkdownDescription: protectionConfigModel.Schema().MarkdownDescription,
				Required:            true,
			},
		},
	}
}

func (*ApplicationSpecModel) FromAPI(ctx context.Context, a api.ApplicationSpecVersion) (ApplicationSpecModel, diag.Diagnostics) {
	var diagnostics diag.Diagnostics
	protectionConfig := func(a api.ProtectionConfig) ProtectionConfigModel {
		var protectionConfigModel ProtectionConfigModel
		m, d := protectionConfigModel.FromAPI(ctx, a)
		diagnostics.Append(d...)
		return m
	}
	var botProtectionSpecModel BotProtectionSpecModel
	var secretModel SecretModel
	var customBlockResponseConfigModel CustomBlockResponseConfigModel
	var doSConfigModel DoSConfigModel
	var intelGatheringModel IntelGatheringModel
	var networkControlsModel NetworkControlsModel
	var remoteHostForwardingModel RemoteHostForwardingModel
	var tlSConfigModel *TLSConfigModel
	return ApplicationSpecModel{
		APISpec: func() APISpecModel {
			var apiSpecModel APISpecModel
			m, d := apiSpecModel.FromAPI(ctx, a.APISpec)
			diagnostics.Append(d...)
			return m
		}(),
		AppID:       types.StringValue(a.AppID),
		AttackTools: protectionConfig(a.AttackTools),
		AutoApplyPatchesSpec: func() AutoApplyPatchesSpecModel {
			var autoApplyPatchesSpec AutoApplyPatchesSpecModel
			m, d := autoApplyPatchesSpec.FromAPI(ctx, a.AutoApplyPatchesSpec)
			diagnostics.Append(d...)
			return m
		}(),
		BanDurationMinutes: types.Int64Value(int64(a.BanDurationMinutes)),
		Body: func() BodyModel {
			var m BodyModel
			return m.FromAPI(a.Body)
		}(),
		BotProtectionSpec: func() BotProtectionSpecModel {
			m, d := botProtectionSpecModel.FromAPI(ctx, a.BotProtectionSpec)
			diagnostics.Append(d...)
			return m
		}(),
		Certificate:         secretModel.FromAPI(ctx, a.Certificate),
		ClickjackingEnabled: types.BoolValue(a.ClickjackingEnabled),
		CMDi:                protectionConfig(a.CMDi),
		CodeInjection:       protectionConfig(a.CodeInjection),
		CSRFEnabled:         types.BoolValue(a.CSRFEnabled),
		CustomRules: func() types.List {
			var customRuleModel CustomRuleModel
			customRules := make([]CustomRuleModel, 0, len(a.CustomRules))
			for _, e := range a.CustomRules {
				customRules = append(customRules, customRuleModel.FromAPI(ctx, e))
			}
			customRuleList, d := types.ListValueFrom(ctx, customRuleModel.Schema().Type(), customRules)
			diagnostics.Append(d...)
			return customRuleList
		}(),
		CustomBlockResponseConfig: customBlockResponseConfigModel.FromAPI(ctx, a.CustomBlockResponseConfig),
		DisableEventIDHeader:      types.BoolValue(a.DisableEventIDHeader),
		DoSConfig:                 doSConfigModel.FromAPI(ctx, a.DoSConfig),
		HeaderSpecs: func() types.List {
			var headerSpecModel HeaderSpecModel
			headerSpecs := make([]HeaderSpecModel, 0, len(a.HeaderSpecs))
			for _, e := range a.HeaderSpecs {
				headerSpecs = append(headerSpecs, headerSpecModel.FromAPI(ctx, e))
			}
			headerSpecList, d := types.ListValueFrom(ctx, headerSpecModel.Schema().Type(), headerSpecs)
			diagnostics.Append(d...)
			return headerSpecList
		}(),
		IntelGathering: intelGatheringModel.FromAPI(ctx, a.IntelGathering),
		LFi:            protectionConfig(a.LFI),
		MalformedReq:   protectionConfig(a.MalformedReq),
		MaliciousUpload: func() MaliciousUploadModel {
			var maliciousUploadModel MaliciousUploadModel
			m, d := maliciousUploadModel.FromAPI(ctx, a.MaliciousUpload)
			diagnostics.Append(d...)
			return m
		}(),
		NetworkControls: func() NetworkControlsModel {
			m, d := networkControlsModel.FromAPI(ctx, a.NetworkControls)
			diagnostics.Append(d...)
			return m
		}(),
		RemoteHostForwarding: remoteHostForwardingModel.FromAPI(a.RemoteHostForwarding),
		ResponseHeaderSpecs: func() types.List {
			var responseHeaderSpecsModel ResponseHeaderSpecsModel
			responseHeaderSpecs := make([]ResponseHeaderSpecsModel, 0, len(a.ResponseHeaderSpecs))
			for _, r := range a.ResponseHeaderSpecs {
				responseHeaderSpecs = append(responseHeaderSpecs, responseHeaderSpecsModel.FromAPI(ctx, r))
			}
			responseHeaderSpecList, d := types.ListValueFrom(ctx, responseHeaderSpecsModel.Schema().Type(), responseHeaderSpecs)
			diagnostics.Append(d...)
			return responseHeaderSpecList
		}(),
		RuleName:              types.StringValue(a.RuleName),
		SessionCookieBan:      types.BoolValue(a.SessionCookieBan),
		SessionCookieEnabled:  types.BoolValue(a.SessionCookieEnabled),
		SessionCookieSameSite: types.StringValue(a.SessionCookieSameSite),
		SessionCookieSecure:   types.BoolValue(a.SessionCookieSecure),
		Shellshock:            protectionConfig(a.Shellshock),
		SQLi:                  protectionConfig(a.SQLi),
		TLSConfig:             tlSConfigModel.FromAPI(a.TLSConfig),
		Version:               types.StringValue(a.Version),
		XSS:                   protectionConfig(a.XSS),
	}, diagnostics
}

func (a *ApplicationSpecModel) ToAPI(ctx context.Context) (api.ApplicationSpecVersion, diag.Diagnostics) {
	var diagnostics diag.Diagnostics
	protectionConfig := func(m ProtectionConfigModel) api.ProtectionConfig {
		p, d := m.ToAPI(ctx)
		diagnostics.Append(d...)
		return p
	}
	return api.ApplicationSpecVersion{
		ApplicationSpec: api.ApplicationSpec{
			APISpec: func() api.APISpec {
				apiSpec, d := a.APISpec.ToAPI(ctx)
				diagnostics.Append(d...)
				return apiSpec
			}(),
			AppID:       a.AppID.ValueString(),
			AttackTools: protectionConfig(a.AttackTools),
			AutoApplyPatchesSpec: func() api.AutoApplyPatchesSpec {
				a, d := a.AutoApplyPatchesSpec.ToAPI(ctx)
				diagnostics.Append(d...)
				return a
			}(),
			BanDurationMinutes: int(a.BanDurationMinutes.ValueInt64()),
			Body:               a.Body.ToAPI(),
			BotProtectionSpec: func() api.BotProtectionSpec {
				b, d := a.BotProtectionSpec.ToAPI(ctx)
				diagnostics.Append(d...)
				return b
			}(),
			Certificate:               a.Certificate.ToAPI(),
			CMDi:                      protectionConfig(a.CMDi),
			ClickjackingEnabled:       a.ClickjackingEnabled.ValueBool(),
			CodeInjection:             protectionConfig(a.CodeInjection),
			CSRFEnabled:               a.CSRFEnabled.ValueBool(),
			CustomBlockResponseConfig: a.CustomBlockResponseConfig.ToAPI(),
			CustomRules: func() []api.CustomRule {
				customRuleModels := make([]CustomRuleModel, 0, len(a.CustomRules.Elements()))
				d := a.CustomRules.ElementsAs(ctx, &customRuleModels, false)
				diagnostics.Append(d...)
				customRules := make([]api.CustomRule, 0, len(customRuleModels))
				for _, customRuleModel := range customRuleModels {
					customRules = append(customRules, customRuleModel.ToAPI())
				}
				return customRules
			}(),
			DisableEventIDHeader: a.DisableEventIDHeader.ValueBool(),
			DoSConfig: func() api.DoSConfig {
				dosConfig, d := a.DoSConfig.ToAPI(ctx)
				diagnostics.Append(d...)
				return dosConfig
			}(),
			HeaderSpecs: func() []api.HeaderSpec {
				headerSpecModels := make([]HeaderSpecModel, 0, len(a.HeaderSpecs.Elements()))
				d := a.HeaderSpecs.ElementsAs(ctx, &headerSpecModels, false)
				diagnostics.Append(d...)
				headerSpecs := make([]api.HeaderSpec, 0, len(headerSpecModels))
				for _, headerSpecModel := range headerSpecModels {
					h, d := headerSpecModel.ToAPI(ctx)
					diagnostics.Append(d...)
					headerSpecs = append(headerSpecs, h)
				}
				return headerSpecs
			}(),
			IntelGathering: a.IntelGathering.ToAPI(),
			LFI:            protectionConfig(a.LFi),
			MalformedReq:   protectionConfig(a.MalformedReq),
			MaliciousUpload: func() api.MaliciousUpload {
				m, d := a.MaliciousUpload.ToAPI(ctx)
				diagnostics.Append(d...)
				return m
			}(),
			NetworkControls: func() api.NetworkControls {
				n, d := a.NetworkControls.ToAPI(ctx)
				diagnostics.Append(d...)
				return n
			}(),
			RemoteHostForwarding: a.RemoteHostForwarding.ToAPI(),
			ResponseHeaderSpecs: func() []api.ResponseHeaderSpec {
				responseHeaderSpecModels := make([]ResponseHeaderSpecsModel, 0, len(a.ResponseHeaderSpecs.Elements()))
				d := a.ResponseHeaderSpecs.ElementsAs(ctx, &responseHeaderSpecModels, false)
				diagnostics.Append(d...)
				responseHeaderSpecs := make([]api.ResponseHeaderSpec, 0, len(responseHeaderSpecModels))
				for _, responseHeaderSpecModel := range responseHeaderSpecModels {
					r, d := responseHeaderSpecModel.ToAPI(ctx)
					diagnostics.Append(d...)
					responseHeaderSpecs = append(responseHeaderSpecs, r)
				}
				return responseHeaderSpecs
			}(),
			RuleName:              a.RuleName.ValueString(),
			SessionCookieBan:      a.SessionCookieBan.ValueBool(),
			SessionCookieEnabled:  a.SessionCookieEnabled.ValueBool(),
			SessionCookieSameSite: a.SessionCookieSameSite.ValueString(),
			SessionCookieSecure:   a.SessionCookieSecure.ValueBool(),
			Shellshock:            protectionConfig(a.Shellshock),
			SQLi:                  protectionConfig(a.SQLi),
			TLSConfig: func() *api.TLSConfig {
				if a.TLSConfig == nil {
					return nil
				}
				t, d := a.TLSConfig.ToAPI()
				diagnostics.Append(d...)
				return &t
			}(),
			XSS: protectionConfig(a.XSS),
		},
		Version: a.Version.ValueString(),
	}, diagnostics
}

type CustomBlockResponseConfigModel struct {
	Body    types.String `tfsdk:"body"`
	Code    types.Int64  `tfsdk:"code"`
	Enabled types.Bool   `tfsdk:"enabled"`
}

// Schema describes the model for Terraform
// TODO: customBlockResponseConfig is required, but all its attributes are optional - does this work as expected?
// No, it does not - after an update we receive the 0 value for all the attributes - effectively making them Required
func (*CustomBlockResponseConfigModel) Schema() schema.Schema {
	return schema.Schema{
		MarkdownDescription: "Custom block HTTP response and HTML page",
		Attributes: map[string]schema.Attribute{
			"body": schema.StringAttribute{
				MarkdownDescription: "Custom HTML for the block response",
				Required:            true,
			},
			"code": schema.Int64Attribute{
				MarkdownDescription: "Custom HTTP response code for the block response",
				Required:            true,
			},
			"enabled": schema.BoolAttribute{
				MarkdownDescription: "Indicates if the custom block response is enabled",
				Required:            true,
			},
		},
	}
}

func (*CustomBlockResponseConfigModel) FromAPI(_ context.Context, a api.CustomBlockResponseConfig) CustomBlockResponseConfigModel {
	return CustomBlockResponseConfigModel{
		Body:    types.StringValue(a.Body),
		Code:    types.Int64Value(int64(a.Code)),
		Enabled: types.BoolValue(a.Enabled),
	}
}

func (c *CustomBlockResponseConfigModel) ToAPI() api.CustomBlockResponseConfig {
	return api.CustomBlockResponseConfig{
		Body:    c.Body.ValueString(),
		Code:    int(c.Code.ValueInt64()),
		Enabled: c.Enabled.ValueBool(),
	}
}

type SecretModel struct {
	Encrypted types.String `tfsdk:"encrypted"`
	Plain     types.String `tfsdk:"plain"`
}

func (*SecretModel) Schema() schema.Schema {
	return schema.Schema{
		MarkdownDescription: "Secret contains the plain and encrypted version of a value (the plain version is never stored in the DB)",
		Attributes: map[string]schema.Attribute{
			"encrypted": schema.StringAttribute{
				MarkdownDescription: "Encrypted value for the secret",
				Computed:            true,
				Optional:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"plain": schema.StringAttribute{
				MarkdownDescription: "Plain text value for the secret. Note: marshalling to JSON will convert to an encrypted value",
				Optional:            true,
				Sensitive:           true,
			},
		},
	}
}

func (*SecretModel) FromAPI(_ context.Context, a api.Secret) SecretModel {
	return SecretModel{
		Encrypted: types.StringValue(a.Encrypted),
		Plain:     types.StringValue(a.Plain),
	}
}

func (s *SecretModel) ToAPI() api.Secret {
	return api.Secret{
		Encrypted: s.Encrypted.ValueString(),
		Plain:     s.Plain.ValueString(),
	}
}

type TLSConfigModel struct {
	HSTSConfig    HSTSConfigModel `tfsdk:"hsts_config"`
	Metadata      *MetadataModel  `tfsdk:"metadata"`
	MinTLSVersion types.String    `tfsdk:"min_tls_version"`
}

func (*TLSConfigModel) Schema() schema.Schema {
	var hstsConfigModel HSTSConfigModel
	var metadataModel MetadataModel
	return schema.Schema{
		MarkdownDescription: "TLSConfig holds the user TLS configuration and the certificate data",
		Attributes: map[string]schema.Attribute{
			"hsts_config": schema.SingleNestedAttribute{
				MarkdownDescription: hstsConfigModel.Schema().MarkdownDescription,
				Attributes:          hstsConfigModel.Schema().Attributes,
				Required:            true,
			},
			"metadata": schema.SingleNestedAttribute{
				MarkdownDescription: metadataModel.Schema().MarkdownDescription,
				Attributes:          metadataModel.Schema().Attributes,
				Required:            true,
			},
			"min_tls_version": schema.StringAttribute{
				MarkdownDescription: "MinTLSVersion is the minimum acceptable TLS version",
				Validators: []validator.String{
					stringvalidator.OneOf("1.0", "1.1", "1.2", "1.3"),
				},
				Required: true,
			},
		},
	}
}

func (*TLSConfigModel) FromAPI(a *api.TLSConfig) *TLSConfigModel {
	if a == nil {
		return nil
	}
	var hstsConfigModel HSTSConfigModel
	var metadataModel MetadataModel
	return &TLSConfigModel{
		HSTSConfig:    hstsConfigModel.FromAPI(a.HSTSConfig),
		Metadata:      metadataModel.FromAPI(*a.Metadata),
		MinTLSVersion: types.StringValue(a.MinTLSVersion),
	}
}

func (t *TLSConfigModel) ToAPI() (api.TLSConfig, diag.Diagnostics) {
	var diagnostics diag.Diagnostics
	return api.TLSConfig{
		HSTSConfig: t.HSTSConfig.ToAPI(),
		Metadata: func() *api.CertificateMeta {
			c, d := t.Metadata.ToAPI()
			diagnostics.Append(d...)
			return &c
		}(),
		MinTLSVersion: t.MinTLSVersion.ValueString(),
	}, diagnostics
}

type HSTSConfigModel struct {
	Enabled           types.Bool  `tfsdk:"enabled"`
	IncludeSubdomains types.Bool  `tfsdk:"include_subdomains"`
	MaxAgeSeconds     types.Int64 `tfsdk:"max_age_seconds"`
	Preload           types.Bool  `tfsdk:"preload"`
}

func (*HSTSConfigModel) Schema() schema.Schema {
	return schema.Schema{
		MarkdownDescription: "HSTSConfig is the HTTP Strict Transport Security configuration in order to enforce HSTS header see: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
		Attributes: map[string]schema.Attribute{
			"enabled": schema.BoolAttribute{
				MarkdownDescription: "Enabled indicates if HSTS enforcement is enabled",
				Required:            true,
			},
			"include_subdomains": schema.BoolAttribute{
				MarkdownDescription: "IncludeSubdomains indicates if this rule applies to all of the site's subdomains as well",
				Required:            true,
			},
			"max_age_seconds": schema.Int64Attribute{
				MarkdownDescription: "maxAgeSeconds is the time (in seconds) that the browser should remember that a site is only be accessed using HTTPS",
				Required:            true,
			},
			"preload": schema.BoolAttribute{
				MarkdownDescription: "Preload indicates if it should support preload",
				Required:            true,
			},
		},
	}
}

func (*HSTSConfigModel) FromAPI(a api.HSTSConfig) HSTSConfigModel {
	return HSTSConfigModel{
		Enabled:           types.BoolValue(a.Enabled),
		IncludeSubdomains: types.BoolValue(a.IncludeSubdomains),
		MaxAgeSeconds:     types.Int64Value(int64(a.MaxAgeSeconds)),
		Preload:           types.BoolValue(a.Preload),
	}
}

func (h *HSTSConfigModel) ToAPI() api.HSTSConfig {
	return api.HSTSConfig{
		Enabled:           h.Enabled.ValueBool(),
		MaxAgeSeconds:     int(h.MaxAgeSeconds.ValueInt64()),
		IncludeSubdomains: h.IncludeSubdomains.ValueBool(),
		Preload:           h.Preload.ValueBool(),
	}
}

type MetadataModel struct {
	IssuerName  types.String `tfsdk:"issuer_name"`
	NotAfter    types.String `tfsdk:"not_after"` // time.Time
	SubjectName types.String `tfsdk:"subject_name"`
}

func (*MetadataModel) Schema() schema.Schema {
	return schema.Schema{
		MarkdownDescription: "Metadata is the certificate metadata",
		Attributes: map[string]schema.Attribute{
			"issuer_name": schema.StringAttribute{
				MarkdownDescription: "IssuerName is the certificate issuer common name",
				Required:            true,
			},
			"not_after": schema.StringAttribute{
				MarkdownDescription: "NotAfter is the time the certificate is not valid (expiry time) in RFC3339 format",
				Required:            true,
			},
			"subject_name": schema.StringAttribute{
				MarkdownDescription: "SubjectName is the certificate subject common name",
				Required:            true,
			},
		},
	}
}

func (*MetadataModel) FromAPI(a api.CertificateMeta) *MetadataModel {
	return &MetadataModel{
		IssuerName:  types.StringValue(a.IssuerName),
		NotAfter:    types.StringValue(a.NotAfter.Format(time.RFC3339)),
		SubjectName: types.StringValue(a.SubjectName),
	}
}

func (m *MetadataModel) ToAPI() (api.CertificateMeta, diag.Diagnostics) {
	var diagnostics diag.Diagnostics
	return api.CertificateMeta{
		IssuerName: m.IssuerName.ValueString(),
		NotAfter: func() time.Time {
			t, err := time.Parse(time.RFC3339, m.NotAfter.ValueString()) // "2019-08-24T14:15:22Z"
			if err != nil {
				diagnostics.AddAttributeError(path.Root("tls_config").AtName("metatada").AtName("not_after"), "time parse", err.Error())
				return time.Time{}
			}
			return t
		}(),
		SubjectName: m.SubjectName.ValueString(),
	}, diagnostics
}

type APISpecModel struct {
	Description              types.String `tfsdk:"description"`
	Endpoints                types.List   `tfsdk:"endpoints"`
	Effect                   types.String `tfsdk:"effect"`
	FallbackEffect           types.String `tfsdk:"fallback_effect"`
	Paths                    types.Set    `tfsdk:"paths"`
	QueryParamFallbackEffect types.String `tfsdk:"query_param_fallback_effect"`
}

func (*APISpecModel) Schema() schema.Schema {
	var endpointModel EndpointModel
	var effect Effect
	var pathModel PathModel
	return schema.Schema{
		MarkdownDescription: "APISpec is an API specification",
		Attributes: map[string]schema.Attribute{
			"description": schema.StringAttribute{
				MarkdownDescription: "Description of the app",
				Required:            true,
			},
			"endpoints": schema.ListNestedAttribute{
				MarkdownDescription: "The app's endpoints",
				NestedObject:        schema.NestedAttributeObject{Attributes: endpointModel.Schema().Attributes},
				Optional:            true,
			},
			"effect":          effect.Attribute(),
			"fallback_effect": effect.Attribute(),
			"paths": schema.SetNestedAttribute{
				MarkdownDescription: pathModel.Schema().MarkdownDescription,
				NestedObject:        schema.NestedAttributeObject{Attributes: pathModel.Schema().Attributes},
				Optional:            true,
			},
			"query_param_fallback_effect": effect.Attribute(),
		},
	}
}

func (*APISpecModel) FromAPI(ctx context.Context, a api.APISpec) (APISpecModel, diag.Diagnostics) {
	var diagnostics diag.Diagnostics
	var effect Effect
	return APISpecModel{
		Description: types.StringValue(a.Description),
		Endpoints: func() types.List {
			var endpointModel EndpointModel
			endpoints := make([]EndpointModel, 0, len(a.Endpoints))
			for _, e := range a.Endpoints {
				endpoints = append(endpoints, endpointModel.FromAPI(e))
			}
			endpointList, diags := types.ListValueFrom(ctx, endpointModel.Schema().Type(), endpoints)
			diagnostics.Append(diags...)
			return endpointList
		}(),
		Effect:         effect.FromAPI(a.Effect),
		FallbackEffect: effect.FromAPI(a.FallbackEffect),
		Paths: func() types.Set {
			var pathModel PathModel
			pathModels := make([]PathModel, 0, len(a.Paths))
			for _, p := range a.Paths {
				pathModels = append(pathModels, pathModel.FromAPI(ctx, p))
			}
			pathSet, diags := types.SetValueFrom(ctx, pathModel.Schema().Type(), pathModels)
			diagnostics.Append(diags...)
			return pathSet
		}(),
		QueryParamFallbackEffect: effect.FromAPI(a.QueryParamFallbackEffect),
	}, diagnostics
}

func (a *APISpecModel) ToAPI(ctx context.Context) (api.APISpec, diag.Diagnostics) {
	var diagnostics diag.Diagnostics
	var effect Effect
	return api.APISpec{
		Description: a.Description.ValueString(),
		Effect:      effect.ToAPI(a.Effect),
		Endpoints: func() []api.Endpoint {
			endpointModels := make([]EndpointModel, 0, len(a.Endpoints.Elements()))
			d := a.Endpoints.ElementsAs(ctx, &endpointModels, false)
			diagnostics.Append(d...)
			endpoints := make([]api.Endpoint, 0, len(endpointModels))
			for _, m := range endpointModels {
				endpoints = append(endpoints, m.ToAPI())
			}
			return endpoints
		}(),
		FallbackEffect: effect.ToAPI(a.FallbackEffect),
		Paths: func() []api.Path {
			models := make([]PathModel, 0, len(a.Paths.Elements()))
			d := a.Paths.ElementsAs(ctx, &models, false)
			diagnostics.Append(d...)
			paths := make([]api.Path, 0, len(models))
			for _, m := range models {
				p, d := m.ToAPI(ctx)
				diagnostics.Append(d...)
				paths = append(paths, p)
			}
			return paths
		}(),
		QueryParamFallbackEffect: effect.ToAPI(a.QueryParamFallbackEffect),
	}, diagnostics
}

type BodyModel struct {
	InspectionLimitExceededEffect types.String `tfsdk:"inspection_limit_exceeded_effect"`
	InspectionSizeBytes           types.Int64  `tfsdk:"inspection_size_bytes"`
	Skip                          types.Bool   `tfsdk:"skip"`
}

func (*BodyModel) Schema() schema.Schema {
	var effect Effect
	return schema.Schema{
		MarkdownDescription: "Represents app configuration related to HTTP Body",
		Attributes: map[string]schema.Attribute{
			"inspection_limit_exceeded_effect": effect.Attribute(),
			"inspection_size_bytes": schema.Int64Attribute{
				Computed:            true,
				Default:             int64default.StaticInt64(131072),
				MarkdownDescription: "InspectionSizeBytes represents the max amount of data to inspect in request body",
				Optional:            true,
			},
			"skip": schema.BoolAttribute{
				Computed:            true,
				Default:             booldefault.StaticBool(false),
				MarkdownDescription: "Skip indicates that body inspection should be skipped",
				Optional:            true,
			},
		},
	}
}

func (*BodyModel) FromAPI(a api.BodyConfig) BodyModel {
	var effect Effect
	return BodyModel{
		InspectionLimitExceededEffect: effect.FromAPI(a.InspectionLimitExceededEffect),
		InspectionSizeBytes:           types.Int64Value(int64(a.InspectionSizeBytes)),
		Skip:                          types.BoolValue(a.Skip),
	}
}

func (b *BodyModel) ToAPI() api.BodyConfig {
	var effect Effect
	return api.BodyConfig{
		InspectionLimitExceededEffect: effect.ToAPI(b.InspectionLimitExceededEffect),
		InspectionSizeBytes:           int(b.InspectionSizeBytes.ValueInt64()),
		Skip:                          b.Skip.ValueBool(),
	}
}

type EndpointModel struct {
	BasePath     types.String `tfsdk:"base_path"`
	ExposedPort  types.Int64  `tfsdk:"exposed_port"`
	GRPC         types.Bool   `tfsdk:"grpc"`
	Host         types.String `tfsdk:"host"`
	HTTP2        types.Bool   `tfsdk:"http2"`
	InternalPort types.Int64  `tfsdk:"internal_port"`
	TLS          types.Bool   `tfsdk:"tls"`
}

func (*EndpointModel) Schema() schema.Schema {
	return schema.Schema{
		MarkdownDescription: "The app's endpoints",
		Attributes: map[string]schema.Attribute{
			"base_path": schema.StringAttribute{
				Computed:            true,
				Default:             stringdefault.StaticString("*"),
				MarkdownDescription: "Base path for the endpoint",
				Optional:            true,
			},
			"exposed_port": schema.Int64Attribute{
				Computed:            true,
				Default:             int64default.StaticInt64(0),
				MarkdownDescription: "Exposed port that the proxy is listening on",
				Optional:            true,
			},
			"grpc": schema.BoolAttribute{
				Computed:            true,
				Default:             booldefault.StaticBool(false),
				MarkdownDescription: "Indicates if the proxy supports gRPC",
				Optional:            true,
			},
			"host": schema.StringAttribute{
				Computed:            true,
				Default:             stringdefault.StaticString("*"),
				MarkdownDescription: "URL address (name or IP) of the endpoint's API specification (for example, petstore.swagger.io). The address can be prefixed with a wildcard (for example, *.swagger.io)",
				Optional:            true,
			},
			"http2": schema.BoolAttribute{
				Computed:            true,
				Default:             booldefault.StaticBool(false),
				MarkdownDescription: "Indicates if the proxy supports HTTP/2",
				Optional:            true,
			},
			"internal_port": schema.Int64Attribute{
				Computed:            true,
				Default:             int64default.StaticInt64(0),
				MarkdownDescription: "Internal port that the application is listening on",
				Optional:            true,
			},
			"tls": schema.BoolAttribute{
				Computed:            true,
				Default:             booldefault.StaticBool(false),
				MarkdownDescription: "Indicates if the connection is secured",
				Optional:            true,
			},
		},
	}
}

func (*EndpointModel) FromAPI(a api.Endpoint) EndpointModel {
	return EndpointModel{
		BasePath:     types.StringValue(a.BasePath),
		ExposedPort:  types.Int64Value(int64(a.ExposedPort)),
		GRPC:         types.BoolValue(a.GRPC),
		Host:         types.StringValue(a.Host),
		HTTP2:        types.BoolValue(a.HTTP2),
		InternalPort: types.Int64Value(int64(a.InternalPort)),
		TLS:          types.BoolValue(a.TLS),
	}
}

func (m *EndpointModel) ToAPI() api.Endpoint {
	return api.Endpoint{
		BasePath:     m.BasePath.ValueString(),
		ExposedPort:  int(m.ExposedPort.ValueInt64()),
		GRPC:         m.GRPC.ValueBool(),
		Host:         m.Host.ValueString(),
		HTTP2:        m.HTTP2.ValueBool(),
		InternalPort: int(m.InternalPort.ValueInt64()),
		TLS:          m.TLS.ValueBool(),
	}
}

type PathModel struct {
	Methods types.Set    `tfsdk:"methods"`
	Path    types.String `tfsdk:"path"`
}

func (*PathModel) Schema() schema.Schema {
	var methodModel MethodModel
	return schema.Schema{
		MarkdownDescription: "Paths of the API endpoints",
		Attributes: map[string]schema.Attribute{
			"methods": schema.SetNestedAttribute{
				MarkdownDescription: "Supported operations for the path (for example, PUT, GET, etc)",
				NestedObject:        schema.NestedAttributeObject{Attributes: methodModel.Schema().Attributes},
				Optional:            true,
			},
			"path": schema.StringAttribute{
				MarkdownDescription: "Relative path to an endpoint, such as `/pet/{petId}`",
				Required:            true,
			},
		},
	}
}

func (*PathModel) FromAPI(ctx context.Context, a api.Path) PathModel {
	var diagnostics diag.Diagnostics
	return PathModel{
		Methods: func() types.Set {
			var methodModel MethodModel
			methods := make([]MethodModel, 0, len(a.Methods))
			for _, e := range a.Methods {
				method, diags := methodModel.FromAPI(ctx, e)
				diagnostics.Append(diags...)
				methods = append(methods, method)
			}
			methodSet, diags := types.SetValueFrom(ctx, methodModel.Schema().Type(), methods)
			diagnostics.Append(diags...)
			return methodSet
		}(),
		Path: types.StringValue(a.Name),
	}
}

func (p *PathModel) ToAPI(ctx context.Context) (api.Path, diag.Diagnostics) {
	var diagnostics diag.Diagnostics
	return api.Path{
		Methods: func() []api.Method {
			methodModels := make([]MethodModel, 0, len(p.Methods.Elements()))
			d := p.Methods.ElementsAs(ctx, &methodModels, false)
			diagnostics.Append(d...)
			methods := make([]api.Method, 0, len(methodModels))
			for _, method := range methodModels {
				m, d := method.ToAPI(ctx)
				diagnostics.Append(d...)
				methods = append(methods, m)
			}
			return methods
		}(),
		Name: p.Path.ValueString(),
	}, diagnostics
}

type MethodModel struct {
	Method     types.String `tfsdk:"method"`
	Parameters types.List   `tfsdk:"parameters"`
}

func (*MethodModel) Schema() schema.Schema {
	var paramModel ParamModel
	return schema.Schema{
		MarkdownDescription: "Supported HTTP operations(for example, PUT, GET, etc)",
		Attributes: map[string]schema.Attribute{
			"method": schema.StringAttribute{
				MarkdownDescription: "HTTP verb (for example, PUT, GET, etc)",
				Required:            true,
			},
			"parameters": schema.ListNestedAttribute{
				MarkdownDescription: "parameters of the http request",
				NestedObject:        schema.NestedAttributeObject{Attributes: paramModel.Schema().Attributes},
				Optional:            true,
			},
		},
	}
}

func (*MethodModel) FromAPI(ctx context.Context, a api.Method) (MethodModel, diag.Diagnostics) {
	var diagnostics diag.Diagnostics
	return MethodModel{
		Method: types.StringValue(a.Name),
		Parameters: func() types.List {
			var parameterModel ParamModel
			parameters := make([]ParamModel, 0, len(a.Parameters))
			for _, p := range a.Parameters {
				parameters = append(parameters, parameterModel.FromAPI(ctx, p))
			}
			parameterList, diags := types.ListValueFrom(ctx, parameterModel.Schema().Type(), parameters)
			diagnostics.Append(diags...)
			return parameterList
		}(),
	}, diagnostics
}

func (m *MethodModel) ToAPI(ctx context.Context) (api.Method, diag.Diagnostics) {
	var diagnostics diag.Diagnostics
	return api.Method{
		Name: m.Method.ValueString(),
		Parameters: func() []api.Param {
			paramModels := make([]ParamModel, 0, len(m.Parameters.Elements()))
			d := m.Parameters.ElementsAs(ctx, &paramModels, false)
			diagnostics.Append(d...)
			params := make([]api.Param, 0, len(paramModels))
			for _, param := range paramModels {
				params = append(params, param.ToAPI())
			}
			return params
		}(),
	}, diagnostics
}

type ParamModel struct {
	AllowEmptyValue types.Bool    `tfsdk:"allow_empty_value"`
	Array           types.Bool    `tfsdk:"array"`
	Explode         types.Bool    `tfsdk:"explode"`
	Location        types.String  `tfsdk:"location"`
	Max             types.Float64 `tfsdk:"max"`
	Min             types.Float64 `tfsdk:"min"`
	Name            types.String  `tfsdk:"name"`
	Required        types.Bool    `tfsdk:"required"`
	Style           types.String  `tfsdk:"style"`
	Type            types.String  `tfsdk:"type"`
}

func (*ParamModel) Schema() schema.Schema {
	return schema.Schema{
		MarkdownDescription: "Parameters the HTTP request",
		Attributes: map[string]schema.Attribute{
			"allow_empty_value": schema.BoolAttribute{
				MarkdownDescription: "Indicates if an empty value is allowed",
				Optional:            true,
			},
			"array": schema.BoolAttribute{
				MarkdownDescription: "Indicates if multiple values of the specified type are allowed",
				Optional:            true,
			},
			"explode": schema.BoolAttribute{
				MarkdownDescription: "Indicates if arrays should generate separate parameters for each array item or object property",
				Optional:            true,
			},
			"location": schema.StringAttribute{
				MarkdownDescription: "location of a parameter in the request",
				Validators: []validator.String{
					stringvalidator.OneOf("body", "cookie", "formData", "header", "json", "multipart", "path", "query", "xml"),
				},
				Required: true,
			},
			"max": schema.Float64Attribute{
				MarkdownDescription: "Maximum allowable value for a numeric parameter",
				Optional:            true,
			},
			"min": schema.Float64Attribute{
				MarkdownDescription: "Minimum allowable value for a numeric parameter",
				Optional:            true,
			},
			"name": schema.StringAttribute{
				MarkdownDescription: "Name of the parameter",
				Required:            true,
			},
			"required": schema.BoolAttribute{
				MarkdownDescription: "Indicates if the parameter is required",
				Optional:            true,
			},
			"style": schema.StringAttribute{
				MarkdownDescription: "Style is a param format style, defined by OpenAPI specification It describes how the parameter value will be serialized depending on the type of the parameter value. Ref: https://swagger.io/docs/specification/serialization/ https://github.com/OAI/OpenAPI-Specification/blob/master/versions/3.0.0.md#style-examples",
				Validators: []validator.String{
					stringvalidator.OneOf("form", "label", "matrix", "pipeDelimited", "simple", "spaceDelimited", "tabDelimited"),
				},
				Optional: true,
			},
			"type": schema.StringAttribute{
				MarkdownDescription: "Type is the type of a parameter, defined by OpenAPI specification Ref: https://github.com/OAI/OpenAPI-Specification/blob/master/versions/2.0.md#data-types",
				Validators: []validator.String{
					stringvalidator.OneOf("array", "boolean", "integer", "number", "object", "string"),
				},
				Required: true,
			},
		},
	}
}

func (*ParamModel) FromAPI(_ context.Context, a api.Param) ParamModel {
	return ParamModel{
		AllowEmptyValue: types.BoolValue(a.AllowEmptyValue),
		Array:           types.BoolValue(a.Array),
		Explode:         types.BoolValue(a.Explode),
		Location:        types.StringValue(a.Location),
		Max:             types.Float64Value(*a.Max),
		Min:             types.Float64Value(*a.Min),
		Name:            types.StringValue(a.Name),
		Required:        types.BoolValue(a.Required),
		Style:           types.StringValue(a.Style),
		Type:            types.StringValue(a.Type),
	}
}

func (p *ParamModel) ToAPI() api.Param {
	return api.Param{
		Array:           p.Array.ValueBool(),
		AllowEmptyValue: p.AllowEmptyValue.ValueBool(),
		Explode:         p.Explode.ValueBool(),
		Location:        p.Location.ValueString(),
		Name:            p.Name.ValueString(),
		Max:             func() *float64 { var f float64; f = p.Max.ValueFloat64(); return &f }(),
		Min:             func() *float64 { var f float64; f = p.Min.ValueFloat64(); return &f }(),
		Required:        p.Required.ValueBool(),
		Style:           p.Style.ValueString(),
		Type:            p.Type.ValueString(),
	}
}

type BotProtectionSpecModel struct {
	InterstitialPage         types.Bool                    `tfsdk:"interstitial_page"`
	JSInjectionSpec          JSInjectionSpecModel          `tfsdk:"js_injection_spec"`
	KnownBotProtectionsSpec  KnownBotProtectionsSpecModel  `tfsdk:"known_bot_protections_spec"`
	ReCAPTCHASpec            ReCAPTCHASpecModel            `tfsdk:"re_captcha_spec"`
	SessionValidation        types.String                  `tfsdk:"session_validation"`
	UnknownBotProtectionSpec UnknownBotProtectionSpecModel `tfsdk:"unknown_bot_protection_spec"`
	UserDefinedBots          types.List                    `tfsdk:"user_defined_bots"`
}

func (*BotProtectionSpecModel) Schema() schema.Schema {
	var jsInjectionSpecModel JSInjectionSpecModel
	var knownBotProtectionsSpecModel KnownBotProtectionsSpecModel
	var reCAPTCHASpecModel ReCAPTCHASpecModel
	var unknownBotProtectionSpecModel UnknownBotProtectionSpecModel
	var userDefinedBotModel UserDefinedBotModel
	var botEffect BotEffect
	return schema.Schema{
		MarkdownDescription: "BotProtectionSpec is the bot protection configuration",
		Attributes: map[string]schema.Attribute{
			"interstitial_page": schema.BoolAttribute{
				Computed:            true,
				Default:             booldefault.StaticBool(false),
				MarkdownDescription: "Indicates whether an interstitial page is served",
				Optional:            true,
			},
			"js_injection_spec": schema.SingleNestedAttribute{
				MarkdownDescription: jsInjectionSpecModel.Schema().MarkdownDescription,
				Attributes:          jsInjectionSpecModel.Schema().Attributes,
				Required:            true,
			},
			"known_bot_protections_spec": schema.SingleNestedAttribute{
				MarkdownDescription: knownBotProtectionsSpecModel.Schema().MarkdownDescription,
				Attributes:          knownBotProtectionsSpecModel.Schema().Attributes,
				Required:            true,
			},
			"re_captcha_spec": schema.SingleNestedAttribute{
				MarkdownDescription: reCAPTCHASpecModel.Schema().MarkdownDescription,
				Attributes:          reCAPTCHASpecModel.Schema().Attributes,
				Required:            true,
			},
			"session_validation": botEffect.Attribute(),
			"unknown_bot_protection_spec": schema.SingleNestedAttribute{
				MarkdownDescription: unknownBotProtectionSpecModel.Schema().MarkdownDescription,
				Attributes:          unknownBotProtectionSpecModel.Schema().Attributes,
				Required:            true,
			},
			"user_defined_bots": schema.ListNestedAttribute{
				MarkdownDescription: userDefinedBotModel.Schema().MarkdownDescription,
				NestedObject:        schema.NestedAttributeObject{Attributes: userDefinedBotModel.Schema().Attributes},
				Required:            true,
			},
		},
	}
}

func (*BotProtectionSpecModel) FromAPI(ctx context.Context, a api.BotProtectionSpec) (BotProtectionSpecModel, diag.Diagnostics) {
	var knownBotProtectionsSpecModel KnownBotProtectionsSpecModel
	var jsInjectionSpecModel JSInjectionSpecModel
	var reCAPTCHASpecModel ReCAPTCHASpecModel
	var botEffect BotEffect
	var unknownBotProtectionSpecModel UnknownBotProtectionSpecModel
	var diagnostics diag.Diagnostics
	return BotProtectionSpecModel{
		InterstitialPage:         types.BoolValue(a.InterstitialPage),
		JSInjectionSpec:          jsInjectionSpecModel.FromAPI(ctx, a.JSInjectionSpec),
		KnownBotProtectionsSpec:  knownBotProtectionsSpecModel.FromAPI(ctx, a.KnownBotProtectionsSpec),
		ReCAPTCHASpec:            reCAPTCHASpecModel.FromAPI(ctx, a.ReCAPTCHASpec),
		SessionValidation:        botEffect.FromAPI(a.SessionValidation),
		UnknownBotProtectionSpec: unknownBotProtectionSpecModel.FromAPI(ctx, a.UnknownBotProtectionSpec),
		UserDefinedBots: func() types.List {
			var userDefinedBotModel UserDefinedBotModel
			userDefinedBots := make([]UserDefinedBotModel, 0, len(a.UserDefinedBots))
			for _, p := range a.UserDefinedBots {
				m, d := userDefinedBotModel.FromAPI(ctx, p)
				diagnostics.Append(d...)
				userDefinedBots = append(userDefinedBots, m)
			}
			userDefinedBotList, diags := types.ListValueFrom(ctx, userDefinedBotModel.Schema().Type(), userDefinedBots)
			diagnostics.Append(diags...)
			return userDefinedBotList
		}(),
	}, diagnostics
}

func (b *BotProtectionSpecModel) ToAPI(ctx context.Context) (api.BotProtectionSpec, diag.Diagnostics) {
	var diagnostics diag.Diagnostics
	var effect Effect
	return api.BotProtectionSpec{
		InterstitialPage: b.InterstitialPage.ValueBool(),
		JSInjectionSpec: api.JSInjectionSpec{
			Enabled:       b.JSInjectionSpec.Enabled.ValueBool(),
			TimeoutEffect: effect.ToAPI(b.JSInjectionSpec.TimeoutEffect),
		},
		KnownBotProtectionsSpec:  b.KnownBotProtectionsSpec.ToAPI(),
		ReCAPTCHASpec:            b.ReCAPTCHASpec.ToAPI(),
		SessionValidation:        effect.ToAPI(b.SessionValidation),
		UnknownBotProtectionSpec: b.UnknownBotProtectionSpec.ToAPI(),
		UserDefinedBots: func() []api.UserDefinedBot {
			userDefinedBotModels := make([]UserDefinedBotModel, 0, len(b.UserDefinedBots.Elements()))
			d := b.UserDefinedBots.ElementsAs(ctx, &userDefinedBotModels, false)
			diagnostics.Append(d...)
			userDefinedBots := make([]api.UserDefinedBot, 0, len(userDefinedBotModels))
			for _, userDefinedBotModel := range userDefinedBotModels {
				u, d := userDefinedBotModel.ToAPI(ctx)
				diagnostics.Append(d...)
				userDefinedBots = append(userDefinedBots, u)
			}
			return userDefinedBots
		}(),
	}, diagnostics
}

type JSInjectionSpecModel struct {
	Enabled       types.Bool   `tfsdk:"enabled"`
	TimeoutEffect types.String `tfsdk:"timeout_effect"`
}

func (*JSInjectionSpecModel) Schema() schema.Schema {
	var botEffect BotEffect
	return schema.Schema{
		MarkdownDescription: "JSInjectionSpec is the JavaScript injection configuration",
		Attributes: map[string]schema.Attribute{
			"enabled": schema.BoolAttribute{
				MarkdownDescription: "Indicates if JavaScript injection is enabled",
				Required:            true,
			},
			"timeout_effect": botEffect.Attribute(),
		},
	}
}

func (*JSInjectionSpecModel) FromAPI(_ context.Context, a api.JSInjectionSpec) JSInjectionSpecModel {
	var botEffect BotEffect
	return JSInjectionSpecModel{
		Enabled:       types.BoolValue(a.Enabled),
		TimeoutEffect: botEffect.FromAPI(a.TimeoutEffect),
	}
}

type KnownBotProtectionsSpecModel struct {
	Archiving            types.String `tfsdk:"archiving"`
	BusinessAnalytics    types.String `tfsdk:"business_analytics"`
	CareerSearch         types.String `tfsdk:"career_search"`
	ContentFeedClients   types.String `tfsdk:"content_feed_clients"`
	Educational          types.String `tfsdk:"educational"`
	Financial            types.String `tfsdk:"financial"`
	MediaSearch          types.String `tfsdk:"media_search"`
	News                 types.String `tfsdk:"news"`
	SearchEngineCrawlers types.String `tfsdk:"search_engine_crawlers"`
}

func (*KnownBotProtectionsSpecModel) Schema() schema.Schema {
	var botEffect BotEffect
	return schema.Schema{
		MarkdownDescription: "KnownBotProtectionsSpec is the known bot protections configuration",
		Attributes: map[string]schema.Attribute{
			"archiving":              botEffect.Attribute(),
			"business_analytics":     botEffect.Attribute(),
			"career_search":          botEffect.Attribute(),
			"content_feed_clients":   botEffect.Attribute(),
			"educational":            botEffect.Attribute(),
			"financial":              botEffect.Attribute(),
			"media_search":           botEffect.Attribute(),
			"news":                   botEffect.Attribute(),
			"search_engine_crawlers": botEffect.Attribute(),
		},
	}
}

func (*KnownBotProtectionsSpecModel) FromAPI(_ context.Context, a api.KnownBotProtectionsSpec) KnownBotProtectionsSpecModel {
	var botEffect BotEffect
	return KnownBotProtectionsSpecModel{
		Archiving:            botEffect.FromAPI(a.Archiving),
		BusinessAnalytics:    botEffect.FromAPI(a.BusinessAnalytics),
		CareerSearch:         botEffect.FromAPI(a.CareerSearch),
		ContentFeedClients:   botEffect.FromAPI(a.ContentFeedClients),
		Educational:          botEffect.FromAPI(a.Educational),
		Financial:            botEffect.FromAPI(a.Financial),
		MediaSearch:          botEffect.FromAPI(a.MediaSearch),
		News:                 botEffect.FromAPI(a.News),
		SearchEngineCrawlers: botEffect.FromAPI(a.SearchEngineCrawlers),
	}
}

func (k *KnownBotProtectionsSpecModel) ToAPI() api.KnownBotProtectionsSpec {
	var botEffect BotEffect
	return api.KnownBotProtectionsSpec{
		Archiving:            botEffect.ToAPI(k.Archiving),
		BusinessAnalytics:    botEffect.ToAPI(k.BusinessAnalytics),
		CareerSearch:         botEffect.ToAPI(k.CareerSearch),
		ContentFeedClients:   botEffect.ToAPI(k.ContentFeedClients),
		Educational:          botEffect.ToAPI(k.Educational),
		Financial:            botEffect.ToAPI(k.Financial),
		MediaSearch:          botEffect.ToAPI(k.MediaSearch),
		News:                 botEffect.ToAPI(k.News),
		SearchEngineCrawlers: botEffect.ToAPI(k.SearchEngineCrawlers),
	}
}

type ReCAPTCHASpecModel struct {
	AllSessions            types.Bool   `tfsdk:"all_sessions"`
	Enabled                types.Bool   `tfsdk:"enabled"`
	SecretKey              SecretModel  `tfsdk:"secret_key"`
	SiteKey                types.String `tfsdk:"site_key"`
	SuccessExpirationHours types.Int64  `tfsdk:"success_expiration_hours"`
	Type                   types.String `tfsdk:"type"`
}

func (*ReCAPTCHASpecModel) Schema() schema.Schema {
	var secretModel SecretModel
	return schema.Schema{
		MarkdownDescription: "ReCAPTCHASpec is the reCAPTCHA configuration",
		Attributes: map[string]schema.Attribute{
			"all_sessions": schema.BoolAttribute{
				MarkdownDescription: "Indicates if the reCAPTCHA page is served at the start of every new session",
				Required:            true,
			},
			"enabled": schema.BoolAttribute{
				MarkdownDescription: "Indicates if reCAPTCHA integration is enabled",
				Required:            true,
			},
			"secret_key": schema.SingleNestedAttribute{
				MarkdownDescription: secretModel.Schema().MarkdownDescription,
				Attributes:          secretModel.Schema().Attributes,
				Required:            true,
			},
			"site_key": schema.StringAttribute{
				MarkdownDescription: "site key to use when invoking the reCAPTCHA service",
				Required:            true,
			},
			"success_expiration_hours": schema.Int64Attribute{
				MarkdownDescription: "Duration for which the indication of reCAPTCHA success is kept. Maximum value is 30 days * 24 = 720 hours",
				Validators: []validator.Int64{
					int64validator.AtLeast(0),
					int64validator.AtMost(720),
				},
				Required: true,
			},
			"type": schema.StringAttribute{
				MarkdownDescription: "indicates whether the ReCaptcha is presented as a checkbox or is invisible",
				Validators: []validator.String{
					stringvalidator.OneOf("checkbox", "invisible"),
				},
				Required: true,
			},
		},
	}
}

func (*ReCAPTCHASpecModel) FromAPI(ctx context.Context, a api.ReCAPTCHASpec) ReCAPTCHASpecModel {
	var secretModel SecretModel
	return ReCAPTCHASpecModel{
		AllSessions:            types.BoolValue(a.AllSessions),
		Enabled:                types.BoolValue(a.Enabled),
		SecretKey:              secretModel.FromAPI(ctx, a.SecretKey),
		SiteKey:                types.StringValue(a.SiteKey),
		SuccessExpirationHours: types.Int64Value(int64(a.SuccessExpirationHours)),
		Type:                   types.StringValue(a.Type),
	}
}

func (r *ReCAPTCHASpecModel) ToAPI() api.ReCAPTCHASpec {
	return api.ReCAPTCHASpec{
		AllSessions:            r.AllSessions.ValueBool(),
		Enabled:                r.Enabled.ValueBool(),
		SecretKey:              r.SecretKey.ToAPI(),
		SiteKey:                r.SiteKey.ValueString(),
		SuccessExpirationHours: int(r.SuccessExpirationHours.ValueInt64()),
		Type:                   r.Type.ValueString(),
	}
}

type UnknownBotProtectionSpecModel struct {
	APILibraries         types.String          `tfsdk:"api_libraries"`
	BotImpersonation     types.String          `tfsdk:"bot_impersonation"`
	BrowserImpersonation types.String          `tfsdk:"browser_impersonation"`
	Generic              types.String          `tfsdk:"generic"`
	HTTPLibraries        types.String          `tfsdk:"http_libraries"`
	RequestAnomalies     RequestAnomaliesModel `tfsdk:"request_anomalies"`
	WebAutomationTools   types.String          `tfsdk:"web_automation_tools"`
	WebScrapers          types.String          `tfsdk:"web_scrapers"`
}

func (*UnknownBotProtectionSpecModel) Schema() schema.Schema {
	var requestAnomaliesModel RequestAnomaliesModel
	var botEffect BotEffect
	return schema.Schema{
		MarkdownDescription: "UnknownBotProtectionSpec is the unknown bot protection configuration",
		Attributes: map[string]schema.Attribute{
			"api_libraries":         botEffect.Attribute(),
			"bot_impersonation":     botEffect.Attribute(),
			"browser_impersonation": botEffect.Attribute(),
			"generic":               botEffect.Attribute(),
			"http_libraries":        botEffect.Attribute(),
			"request_anomalies": schema.SingleNestedAttribute{
				MarkdownDescription: requestAnomaliesModel.Schema().MarkdownDescription,
				Attributes:          requestAnomaliesModel.Schema().Attributes,
				Required:            true,
			},
			"web_automation_tools": botEffect.Attribute(),
			"web_scrapers":         botEffect.Attribute(),
		},
	}
}

func (*UnknownBotProtectionSpecModel) FromAPI(ctx context.Context, a api.UnknownBotProtectionSpec) UnknownBotProtectionSpecModel {
	var requestAnomaliesModel RequestAnomaliesModel
	var botEffect BotEffect
	return UnknownBotProtectionSpecModel{
		APILibraries:         botEffect.FromAPI(a.APILibraries),
		BotImpersonation:     botEffect.FromAPI(a.BotImpersonation),
		BrowserImpersonation: botEffect.FromAPI(a.BrowserImpersonation),
		Generic:              botEffect.FromAPI(a.Generic),
		HTTPLibraries:        botEffect.FromAPI(a.HTTPLibraries),
		RequestAnomalies:     requestAnomaliesModel.FromAPI(ctx, a.RequestAnomalies),
		WebAutomationTools:   botEffect.FromAPI(a.WebAutomationTools),
		WebScrapers:          botEffect.FromAPI(a.WebScrapers),
	}
}

func (u *UnknownBotProtectionSpecModel) ToAPI() api.UnknownBotProtectionSpec {
	var botEffect BotEffect
	return api.UnknownBotProtectionSpec{
		APILibraries:         botEffect.ToAPI(u.APILibraries),
		BotImpersonation:     botEffect.ToAPI(u.BotImpersonation),
		BrowserImpersonation: botEffect.ToAPI(u.BrowserImpersonation),
		Generic:              botEffect.ToAPI(u.Generic),
		HTTPLibraries:        botEffect.ToAPI(u.HTTPLibraries),
		RequestAnomalies:     u.RequestAnomalies.ToAPI(),
		WebAutomationTools:   botEffect.ToAPI(u.WebAutomationTools),
		WebScrapers:          botEffect.ToAPI(u.WebScrapers),
	}
}

type RequestAnomaliesModel struct {
	Effect    types.String `tfsdk:"effect"`
	Threshold types.Int64  `tfsdk:"threshold"`
}

func (*RequestAnomaliesModel) Schema() schema.Schema {
	var botEffect BotEffect
	return schema.Schema{
		MarkdownDescription: "RequestAnomalies is the request anomalies configuration",
		Attributes: map[string]schema.Attribute{
			"effect": botEffect.Attribute(),
			"threshold": schema.Int64Attribute{
				Computed:            true,
				Default:             int64default.StaticInt64(3),
				MarkdownDescription: "Threshold is the score threshold for which request anomaly violation is triggered",
				Validators: []validator.Int64{
					int64validator.OneOf(3, 6, 9),
				},
				Optional: true,
			},
		},
	}
}

func (*RequestAnomaliesModel) FromAPI(_ context.Context, a api.RequestAnomalies) RequestAnomaliesModel {
	var botEffect BotEffect
	return RequestAnomaliesModel{
		Effect:    botEffect.FromAPI(a.Effect),
		Threshold: types.Int64Value(int64(a.Threshold)),
	}
}

func (r *RequestAnomaliesModel) ToAPI() api.RequestAnomalies {
	var botEffect BotEffect
	return api.RequestAnomalies{
		Effect:    botEffect.ToAPI(r.Effect),
		Threshold: int(r.Threshold.ValueInt64()),
	}
}

type UserDefinedBotModel struct {
	Effect       types.String `tfsdk:"effect"`
	HeaderName   types.String `tfsdk:"header_name"`
	HeaderValues types.List   `tfsdk:"header_values"`
	Name         types.String `tfsdk:"name"`
	Subnets      types.List   `tfsdk:"subnets"`
}

func (*UserDefinedBotModel) Schema() schema.Schema {
	var botEffect BotEffect
	return schema.Schema{
		MarkdownDescription: "UnknownBotProtectionSpec is the unknown bot protection configuration",
		Attributes: map[string]schema.Attribute{
			"effect": botEffect.Attribute(),
			"header_name": schema.StringAttribute{
				MarkdownDescription: "Header name which defines the bot",
				Required:            true,
			},
			"header_values": schema.ListAttribute{
				MarkdownDescription: "Header values corresponding to the header name. Can contain wildcards",
				ElementType:         types.StringType,
				Required:            true,
			},
			"name": schema.StringAttribute{
				MarkdownDescription: "name for the bot",
				Required:            true,
			},
			"subnets": schema.ListAttribute{
				MarkdownDescription: "Subnets where the bot originates. Specify using network lists",
				ElementType:         types.StringType,
				Required:            true,
			},
		},
	}
}

func (*UserDefinedBotModel) FromAPI(ctx context.Context, a api.UserDefinedBot) (UserDefinedBotModel, diag.Diagnostics) {
	var diagnostics diag.Diagnostics
	var botEffect BotEffect
	return UserDefinedBotModel{
		Effect:     botEffect.FromAPI(a.Effect),
		HeaderName: types.StringValue(a.HeaderName),
		HeaderValues: func() types.List {
			headerValueList, diags := types.ListValueFrom(ctx, types.StringType, a.HeaderValues)
			diagnostics.Append(diags...)
			return headerValueList
		}(),
		Name: types.StringValue(a.Name),
		Subnets: func() types.List {
			subnetList, diags := types.ListValueFrom(ctx, types.StringType, a.Subnets)
			diagnostics.Append(diags...)
			return subnetList
		}(),
	}, diagnostics
}

func (u *UserDefinedBotModel) ToAPI(ctx context.Context) (api.UserDefinedBot, diag.Diagnostics) {
	var diagnostics diag.Diagnostics
	var botEffect BotEffect
	return api.UserDefinedBot{
		Effect:     botEffect.ToAPI(u.Effect),
		HeaderName: u.HeaderName.ValueString(),
		HeaderValues: func() []string {
			headerValues := make([]string, 0, len(u.HeaderValues.Elements()))
			diags := u.HeaderValues.ElementsAs(ctx, &headerValues, false)
			diagnostics.Append(diags...)
			return headerValues
		}(),
		Name: u.Name.ValueString(),
		Subnets: func() []string {
			subnets := make([]string, 0, len(u.Subnets.Elements()))
			diags := u.Subnets.ElementsAs(ctx, &subnets, false)
			diagnostics.Append(diags...)
			return subnets
		}(),
	}, diagnostics
}

type AutoApplyPatchesSpecModel struct {
	Effect types.String `tfsdk:"effect"`
}

func (*AutoApplyPatchesSpecModel) Schema() schema.Schema {
	var effect Effect
	return schema.Schema{
		MarkdownDescription: "ProtectionConfig represents a WAAS protection configuration",
		Attributes: map[string]schema.Attribute{
			"effect": effect.Attribute(),
		},
	}
}

func (*AutoApplyPatchesSpecModel) FromAPI(_ context.Context, a api.AutoApplyPatchesSpec) (AutoApplyPatchesSpecModel, diag.Diagnostics) {
	var effect Effect
	return AutoApplyPatchesSpecModel{
		Effect: effect.FromAPI(a.Effect),
	}, nil
}

func (p *AutoApplyPatchesSpecModel) ToAPI(_ context.Context) (api.AutoApplyPatchesSpec, diag.Diagnostics) {
	var effect Effect
	return api.AutoApplyPatchesSpec{
		Effect: effect.ToAPI(p.Effect),
	}, nil
}

type ProtectionConfigModel struct {
	Effect          types.String `tfsdk:"effect"`
	ExceptionFields types.List   `tfsdk:"exception_fields"`
}

type protectionConfigModelDefaultValue struct {
}

func (p protectionConfigModelDefaultValue) Description(_ context.Context) string {
	return fmt.Sprintf("If value is not configured, defaults to a disabled protection")
}

func (p protectionConfigModelDefaultValue) MarkdownDescription(ctx context.Context) string {
	return p.Description(ctx)
}

func (p protectionConfigModelDefaultValue) DefaultObject(_ context.Context, _ defaults.ObjectRequest, response *defaults.ObjectResponse) {
	response.PlanValue = types.ObjectValueMust(map[string]attr.Type{"effect": types.StringType}, map[string]attr.Value{"effect": types.StringValue("disabled")})
}

func protectionConfigDefault() defaults.Object {
	return protectionConfigModelDefaultValue{}
}

func (*ProtectionConfigModel) Schema() schema.Schema {
	var exceptionFieldModel ExceptionFieldModel
	var effect Effect
	return schema.Schema{
		MarkdownDescription: "ProtectionConfig represents a WAAS protection configuration",
		Attributes: map[string]schema.Attribute{
			"effect": effect.Attribute(),
			"exception_fields": schema.ListNestedAttribute{
				Computed:            true,
				Default:             listdefault.StaticValue(types.ListValueMust(exceptionFieldModel.Schema().Type(), []attr.Value{})),
				MarkdownDescription: "Exceptions",
				NestedObject:        schema.NestedAttributeObject{Attributes: exceptionFieldModel.Schema().Attributes},
				Optional:            true,
			},
		},
	}
}

func (*ProtectionConfigModel) FromAPI(ctx context.Context, a api.ProtectionConfig) (ProtectionConfigModel, diag.Diagnostics) {
	var diagnostics diag.Diagnostics
	var effect Effect
	return ProtectionConfigModel{
		Effect: effect.FromAPI(a.Effect),
		ExceptionFields: func() types.List {
			var exceptionField ExceptionFieldModel
			exceptionFields := make([]ExceptionFieldModel, 0, len(a.ExceptionFields))
			for _, p := range a.ExceptionFields {
				exceptionFields = append(exceptionFields, exceptionField.FromAPI(ctx, p))
			}
			exceptionFieldList, diags := types.ListValueFrom(ctx, exceptionField.Schema().Type(), exceptionFields)
			diagnostics.Append(diags...)
			return exceptionFieldList
		}(),
	}, diagnostics
}

func (p *ProtectionConfigModel) ToAPI(ctx context.Context) (api.ProtectionConfig, diag.Diagnostics) {
	var diagnostics diag.Diagnostics
	exceptionFields := func(list types.List) []api.ExceptionField {
		slice := make([]ExceptionFieldModel, 0, len(list.Elements()))
		diags := list.ElementsAs(ctx, &slice, false)
		diagnostics.Append(diags...)
		exceptionFields := make([]api.ExceptionField, 0, len(slice))
		for _, efm := range slice {
			exceptionFields = append(exceptionFields, efm.ToAPI())
		}
		return exceptionFields
	}
	var effect Effect
	return api.ProtectionConfig{
		Effect:          effect.ToAPI(p.Effect),
		ExceptionFields: exceptionFields(p.ExceptionFields),
	}, diagnostics
}

type ExceptionFieldModel struct {
	Key      types.String `tfsdk:"key"`
	Location types.String `tfsdk:"location"`
}

func (*ExceptionFieldModel) Schema() schema.Schema {
	return schema.Schema{
		MarkdownDescription: "Defines an exception to a protection rule",
		Attributes: map[string]schema.Attribute{
			"key": schema.StringAttribute{
				MarkdownDescription: "Key name that when present triggers exception",
				Required:            true,
			},
			"location": schema.StringAttribute{
				MarkdownDescription: "Location indicates exception http field location",
				Validators: []validator.String{
					stringvalidator.OneOf("body", "cookie", "header", "JSONPath", "path", "query", "queryValues", "rawBody", "UserAgentHeader", "XMLPath"),
				},
				Required: true,
			},
		},
	}
}

func (*ExceptionFieldModel) FromAPI(_ context.Context, a api.ExceptionField) ExceptionFieldModel {
	return ExceptionFieldModel{
		Key:      types.StringValue(a.Key),
		Location: types.StringValue(a.Location),
	}
}

func (e *ExceptionFieldModel) ToAPI() api.ExceptionField {
	return api.ExceptionField{
		Key:      e.Key.ValueString(),
		Location: e.Location.ValueString(),
	}
}

type CustomRuleModel struct {
	Action types.String `tfsdk:"action"`
	Effect types.String `tfsdk:"effect"`
	ID     types.Int64  `tfsdk:"id"`
}

func (*CustomRuleModel) Schema() schema.Schema {
	var customRuleEffect CustomRuleEffect
	return schema.Schema{
		MarkdownDescription: "Custom rule reference",
		Attributes: map[string]schema.Attribute{
			"action": schema.StringAttribute{
				MarkdownDescription: "Action to perform if the custom rule applies",
				Validators: []validator.String{
					stringvalidator.OneOf("audit", "incident"),
				},
				Required: true,
			},
			"effect": customRuleEffect.Attribute(),
			"id": schema.Int64Attribute{
				MarkdownDescription: "Custom rule ID",
				Required:            true,
			},
		},
	}
}

func (*CustomRuleModel) FromAPI(_ context.Context, a api.CustomRule) CustomRuleModel {
	var customRuleEffect CustomRuleEffect
	return CustomRuleModel{
		Action: types.StringValue(a.Action),
		Effect: customRuleEffect.FromAPI(a.Effect),
		ID:     types.Int64Value(int64(a.ID)),
	}
}

func (c *CustomRuleModel) ToAPI() api.CustomRule {
	var customRuleEffect CustomRuleEffect
	return api.CustomRule{
		Action: c.Action.ValueString(),
		Effect: customRuleEffect.ToAPI(c.Effect),
		ID:     int(c.ID.ValueInt64()),
	}
}

type DoSConfigModel struct {
	AlertRates           DoSRatesModel `tfsdk:"alert_rates"`
	BanRates             DoSRatesModel `tfsdk:"ban_rates"`
	Enabled              types.Bool    `tfsdk:"enabled"`
	ExcludedNetworkLists types.List    `tfsdk:"excluded_network_lists"`
	MatchConditions      types.List    `tfsdk:"match_conditions"`
	TrackSession         types.Bool    `tfsdk:"track_session"`
}

func (*DoSConfigModel) Schema() schema.Schema {
	var doSRatesModel DoSRatesModel
	var matchConditionsModel MatchConditionModel
	return schema.Schema{
		MarkdownDescription: "DoSConfig is a dos policy specification",
		Attributes: map[string]schema.Attribute{
			"alert_rates": schema.SingleNestedAttribute{
				MarkdownDescription: "specifies DoS requests rates (thresholds) at which to alert",
				Attributes:          doSRatesModel.Schema().Attributes,
				Required:            true,
			},
			"ban_rates": schema.SingleNestedAttribute{
				MarkdownDescription: "specifies DoS requests rates (thresholds) at which to ban",
				Attributes:          doSRatesModel.Schema().Attributes,
				Required:            true,
			},
			"enabled": schema.BoolAttribute{
				MarkdownDescription: "indicates if DoS protection is enabled",
				Required:            true,
			},
			"excluded_network_lists": schema.ListAttribute{
				MarkdownDescription: "Network IPs to exclude from DoS tracking",
				ElementType:         types.StringType,
				Optional:            true,
			},
			"match_conditions": schema.ListNestedAttribute{
				MarkdownDescription: matchConditionsModel.Schema().MarkdownDescription,
				NestedObject:        schema.NestedAttributeObject{Attributes: matchConditionsModel.Schema().Attributes},
				Optional:            true,
			},
			"track_session": schema.BoolAttribute{
				MarkdownDescription: "Indicates if the custom session ID generated during bot protection flow is tracked",
				Optional:            true,
			},
		},
	}
}

func (*DoSConfigModel) FromAPI(ctx context.Context, a api.DoSConfig) DoSConfigModel {
	var dosRatesModel DoSRatesModel
	var diagnostics diag.Diagnostics
	return DoSConfigModel{
		AlertRates: dosRatesModel.FromAPI(ctx, a.AlertRates),
		BanRates:   dosRatesModel.FromAPI(ctx, a.BanRates),
		Enabled:    types.BoolValue(a.Enabled),
		ExcludedNetworkLists: func() types.List {
			l, d := types.ListValueFrom(ctx, types.StringType, a.ExcludedNetworkLists)
			if d.HasError() {
				diagnostics.Append(d...)
			}
			return l
		}(),
		MatchConditions: func() types.List {
			var matchConditionModel MatchConditionModel
			matchConditions := make([]MatchConditionModel, 0, len(a.MatchConditions))
			for _, e := range a.MatchConditions {
				m, d := matchConditionModel.FromAPI(ctx, e)
				diagnostics.Append(d...)
				matchConditions = append(matchConditions, m)
			}
			MatchConditionList, diags := types.ListValueFrom(ctx, matchConditionModel.Schema().Type(), matchConditions)
			diagnostics.Append(diags...)
			return MatchConditionList
		}(),
		TrackSession: types.BoolValue(a.TrackSession),
	}
}

func (d *DoSConfigModel) ToAPI(ctx context.Context) (api.DoSConfig, diag.Diagnostics) {
	var diagnostics diag.Diagnostics
	strings := func(list types.List) []string {
		strings := make([]string, 0, len(list.Elements()))
		diagnostics.Append(list.ElementsAs(ctx, &strings, false)...)
		return strings
	}
	return api.DoSConfig{
		AlertRates:           d.AlertRates.ToAPI(),
		BanRates:             d.BanRates.ToAPI(),
		Enabled:              d.Enabled.ValueBool(),
		ExcludedNetworkLists: strings(d.ExcludedNetworkLists),
		MatchConditions: func() []api.DoSMatchCondition {
			matchConditionModels := make([]MatchConditionModel, 0, len(d.MatchConditions.Elements()))
			diags := d.MatchConditions.ElementsAs(ctx, &matchConditionModels, false)
			diagnostics.Append(diags...)
			matchConditions := make([]api.DoSMatchCondition, 0, len(matchConditionModels))
			for _, matchConditionModel := range matchConditionModels {
				m, diags := matchConditionModel.ToAPI(ctx)
				diagnostics.Append(diags...)
				matchConditions = append(matchConditions, m)
			}
			return matchConditions
		}(),
		TrackSession: d.TrackSession.ValueBool(),
	}, diagnostics
}

type DoSRatesModel struct {
	Average types.Int64 `tfsdk:"average"`
	Burst   types.Int64 `tfsdk:"burst"`
}

func (*DoSRatesModel) Schema() schema.Schema {
	return schema.Schema{
		MarkdownDescription: "DoSRates specifies dos requests rates (thresholds)",
		Attributes: map[string]schema.Attribute{
			"average": schema.Int64Attribute{
				MarkdownDescription: "Average request rate (requests / second) over 120 seconds",
				Optional:            true,
			},
			"burst": schema.Int64Attribute{
				MarkdownDescription: "Burst request rate (requests / second) over 5 seconds",
				Optional:            true,
			},
		},
	}
}

func (*DoSRatesModel) FromAPI(_ context.Context, a api.DoSRates) DoSRatesModel {
	return DoSRatesModel{
		Average: types.Int64Value(int64(a.Average)),
		Burst:   types.Int64Value(int64(a.Burst)),
	}
}

func (d *DoSRatesModel) ToAPI() api.DoSRates {
	return api.DoSRates{
		Average: int(d.Average.ValueInt64()),
		Burst:   int(d.Burst.ValueInt64()),
	}
}

type MatchConditionModel struct {
	FileTypes          types.List `tfsdk:"file_types"`
	Methods            types.List `tfsdk:"methods"`
	ResponseCodeRanges types.List `tfsdk:"response_code_ranges"`
}

func (*MatchConditionModel) Schema() schema.Schema {
	var responseCodeRanges ResponseCodeRangesModel
	return schema.Schema{
		MarkdownDescription: "Conditions on which to match to track a request. The conditions are \"OR\"'d together during the check.",
		Attributes: map[string]schema.Attribute{
			"file_types": schema.ListAttribute{
				MarkdownDescription: "File types for request matching",
				ElementType:         types.StringType,
				Optional:            true,
			},
			"methods": schema.ListAttribute{
				MarkdownDescription: "HTTP methods for request matching",
				ElementType:         types.StringType,
				Optional:            true,
			},
			"response_code_ranges": schema.ListNestedAttribute{
				MarkdownDescription: responseCodeRanges.Schema().MarkdownDescription,
				NestedObject:        schema.NestedAttributeObject{Attributes: responseCodeRanges.Schema().Attributes},
				Optional:            true,
			},
		},
	}
}

func (*MatchConditionModel) FromAPI(ctx context.Context, a api.DoSMatchCondition) (MatchConditionModel, diag.Diagnostics) {
	var diagnostics diag.Diagnostics
	return MatchConditionModel{
		FileTypes: func() types.List {
			l, d := types.ListValueFrom(ctx, types.StringType, a.FileTypes)
			diagnostics.Append(d...)
			return l
		}(),
		Methods: func() types.List {
			l, d := types.ListValueFrom(ctx, types.StringType, a.Methods)
			diagnostics.Append(d...)
			return l
		}(),
		ResponseCodeRanges: func() types.List {
			var responseCodeRangesModel ResponseCodeRangesModel
			responseCodeRanges := make([]ResponseCodeRangesModel, 0, len(a.ResponseCodeRanges))
			for _, e := range a.ResponseCodeRanges {
				responseCodeRanges = append(responseCodeRanges, responseCodeRangesModel.FromAPI(ctx, e))
			}
			responseCodeRangesList, diags := types.ListValueFrom(ctx, responseCodeRangesModel.Schema().Type(), responseCodeRanges)
			diagnostics.Append(diags...)
			return responseCodeRangesList
		}(),
	}, diagnostics
}

func (m *MatchConditionModel) ToAPI(ctx context.Context) (api.DoSMatchCondition, diag.Diagnostics) {
	var diagnostics diag.Diagnostics
	strings := func(list types.List) []string {
		strings := make([]string, 0, len(list.Elements()))
		diagnostics.Append(list.ElementsAs(ctx, &strings, false)...)
		return strings
	}
	return api.DoSMatchCondition{
		FileTypes: strings(m.FileTypes),
		Methods:   strings(m.Methods),
		ResponseCodeRanges: func() []api.StatusCodeRange {
			responseCodeRangesModels := make([]ResponseCodeRangesModel, 0, len(m.ResponseCodeRanges.Elements()))
			diags := m.ResponseCodeRanges.ElementsAs(ctx, &responseCodeRangesModels, false)
			diagnostics.Append(diags...)
			statusCodeRanges := make([]api.StatusCodeRange, 0, len(responseCodeRangesModels))
			for _, responseCodeRangesModel := range responseCodeRangesModels {
				statusCodeRanges = append(statusCodeRanges, responseCodeRangesModel.ToAPI())
			}
			return statusCodeRanges
		}(),
	}, diagnostics
}

type ResponseCodeRangesModel struct {
	End   types.Int64 `tfsdk:"end"`
	Start types.Int64 `tfsdk:"start"`
}

func (*ResponseCodeRangesModel) Schema() schema.Schema {
	return schema.Schema{
		MarkdownDescription: "A range of HTTP status codes for response matching",
		Attributes: map[string]schema.Attribute{
			"end": schema.Int64Attribute{
				MarkdownDescription: "End of the range. Can be omitted if using a single status code",
				Optional:            true,
			},
			"start": schema.Int64Attribute{
				MarkdownDescription: "Start of the range. Can also be used alone for a single, non-range value",
				Required:            true,
			},
		},
	}
}

func (*ResponseCodeRangesModel) FromAPI(_ context.Context, a api.StatusCodeRange) ResponseCodeRangesModel {
	return ResponseCodeRangesModel{
		End:   types.Int64Value(int64(a.End)),
		Start: types.Int64Value(int64(a.Start)),
	}
}

func (r *ResponseCodeRangesModel) ToAPI() api.StatusCodeRange {
	return api.StatusCodeRange{
		End:   int(r.End.ValueInt64()),
		Start: int(r.Start.ValueInt64()),
	}
}

type HeaderSpecModel struct {
	Allow    types.Bool   `tfsdk:"allow"`
	Effect   types.String `tfsdk:"effect"`
	Name     types.String `tfsdk:"name"`
	Required types.Bool   `tfsdk:"required"`
	Values   types.List   `tfsdk:"values"`
}

func (*HeaderSpecModel) Schema() schema.Schema {
	var headerSpecEffect HeaderSpecEffect
	return schema.Schema{
		MarkdownDescription: "Configuration for inspecting HTTP headers",
		Attributes: map[string]schema.Attribute{
			"allow": schema.BoolAttribute{
				MarkdownDescription: "Indicates if the flow is to be allowed",
				Required:            true,
			},
			"effect": headerSpecEffect.Attribute(),
			"name": schema.StringAttribute{
				MarkdownDescription: "Name of key in header",
				Required:            true,
			},
			"required": schema.BoolAttribute{
				MarkdownDescription: "Indicates if the header must be present",
				Optional:            true,
			},
			"values": schema.ListAttribute{
				MarkdownDescription: "Wildcard expressions that represent the header value to match",
				ElementType:         types.StringType,
				Required:            true,
			},
		},
	}
}

func (*HeaderSpecModel) FromAPI(ctx context.Context, a api.HeaderSpec) HeaderSpecModel {
	var diagnostics diag.Diagnostics
	var headerSpecEffect HeaderSpecEffect
	return HeaderSpecModel{
		Allow:    types.BoolValue(a.Allow),
		Effect:   headerSpecEffect.FromAPI(a.Effect),
		Name:     types.StringValue(a.Name),
		Required: types.BoolValue(a.Required),
		Values: func() types.List {
			l, d := types.ListValueFrom(ctx, types.StringType, a.Values)
			diagnostics.Append(d...)
			return l
		}(),
	}
}

func (h *HeaderSpecModel) ToAPI(ctx context.Context) (api.HeaderSpec, diag.Diagnostics) {
	var diagnostics diag.Diagnostics
	var headerSpecEffect HeaderSpecEffect
	return api.HeaderSpec{
		Allow:    h.Allow.ValueBool(),
		Effect:   headerSpecEffect.ToAPI(h.Effect),
		Name:     h.Name.ValueString(),
		Required: h.Required.ValueBool(),
		Values: func() []string {
			strings := make([]string, 0, len(h.Values.Elements()))
			diagnostics.Append(h.Values.ElementsAs(ctx, &strings, false)...)
			return strings
		}(),
	}, diagnostics
}

type IntelGatheringModel struct {
	InfoLeakageEffect         types.String `tfsdk:"info_leakage_effect"`
	RemoveFingerprintsEnabled types.Bool   `tfsdk:"remove_fingerprints_enabled"`
}

func (*IntelGatheringModel) Schema() schema.Schema {
	var effect Effect
	return schema.Schema{
		MarkdownDescription: "IntelGathering is the configuration for intelligence gathering protections",
		Attributes: map[string]schema.Attribute{
			"info_leakage_effect": effect.Attribute(),
			"remove_fingerprints_enabled": schema.BoolAttribute{
				MarkdownDescription: "Indicates if server fingerprints should be removed",
				Required:            true,
			},
		},
	}
}

func (*IntelGatheringModel) FromAPI(_ context.Context, a api.IntelGathering) IntelGatheringModel {
	var effect Effect
	return IntelGatheringModel{
		InfoLeakageEffect:         effect.FromAPI(a.InfoLeakageEffect),
		RemoveFingerprintsEnabled: types.BoolValue(a.RemoveFingerprintsEnabled),
	}
}

func (i *IntelGatheringModel) ToAPI() api.IntelGathering {
	var effect Effect
	return api.IntelGathering{
		InfoLeakageEffect:         effect.ToAPI(i.InfoLeakageEffect),
		RemoveFingerprintsEnabled: i.RemoveFingerprintsEnabled.ValueBool(),
	}
}

type MaliciousUploadModel struct {
	AllowedExtensions types.List   `tfsdk:"allowed_extensions"`
	AllowedFileTypes  types.List   `tfsdk:"allowed_file_types"`
	Effect            types.String `tfsdk:"effect"`
}

func (*MaliciousUploadModel) Schema() schema.Schema {
	var effect Effect
	return schema.Schema{
		MarkdownDescription: "MaliciousUploadConfig is the configuration for file upload protection",
		Attributes: map[string]schema.Attribute{
			"allowed_extensions": schema.ListAttribute{
				MarkdownDescription: "Allowed file extensions",
				ElementType:         types.StringType,
				Required:            true,
			},
			"allowed_file_types": schema.ListAttribute{
				MarkdownDescription: "Allowed well-known file types",
				ElementType:         types.StringType,
				Validators: []validator.List{
					listvalidator.ValueStringsAre(stringvalidator.OneOf("aac", "avi", "bmp", "gif", "gzip", "ico", "jpeg", "mp3", "mp4", "odf", "officeLegacy", "officeOoxml", "pdf", "png", "rar", "wav", "zip", "7zip")),
				},
				Required: true,
			},
			"effect": effect.Attribute(),
		},
	}
}

func (*MaliciousUploadModel) FromAPI(ctx context.Context, a api.MaliciousUpload) (MaliciousUploadModel, diag.Diagnostics) {
	var diagnostics diag.Diagnostics
	var effect Effect
	return MaliciousUploadModel{
		AllowedExtensions: func() types.List {
			l, d := types.ListValueFrom(ctx, types.StringType, a.AllowedExtensions)
			diagnostics.Append(d...)
			return l
		}(),
		AllowedFileTypes: func() types.List {
			l, d := types.ListValueFrom(ctx, types.StringType, a.AllowedFileTypes)
			diagnostics.Append(d...)
			return l
		}(),
		Effect: effect.FromAPI(a.Effect),
	}, diagnostics
}

func (m *MaliciousUploadModel) ToAPI(ctx context.Context) (api.MaliciousUpload, diag.Diagnostics) {
	var diagnostics diag.Diagnostics
	var effect Effect
	strings := func(list types.List) []string {
		strings := make([]string, 0, len(list.Elements()))
		diagnostics.Append(list.ElementsAs(ctx, &strings, false)...)
		return strings
	}
	return api.MaliciousUpload{
		AllowedExtensions: strings(m.AllowedExtensions),
		AllowedFileTypes:  strings(m.AllowedFileTypes),
		Effect:            effect.ToAPI(m.Effect),
	}, diagnostics
}

// TODO: Lagrange added attribute
type NetworkControlsModel struct {
	AdvancedProtectionEffect types.String        `tfsdk:"advanced_protection_effect"`
	CountriesAccess          AccessControlsModel `tfsdk:"countries"`
	ExceptionSubnets         types.List          `tfsdk:"exception_subnets"`
	Subnets                  AccessControlsModel `tfsdk:"subnets"`
}

func (*NetworkControlsModel) Schema() schema.Schema {
	var accessControlsModel AccessControlsModel
	var effect Effect
	return schema.Schema{
		MarkdownDescription: "NetworkControls contains the network controls config (e.g., access controls for IPs and countries)",
		Attributes: map[string]schema.Attribute{
			"advanced_protection_effect": effect.Attribute(),
			"countries": schema.SingleNestedAttribute{
				MarkdownDescription: accessControlsModel.Schema().MarkdownDescription,
				Attributes:          accessControlsModel.Schema().Attributes,
				Required:            true,
			},
			"exception_subnets": schema.ListAttribute{
				MarkdownDescription: "Network lists for which requests completely bypass WAAS checks and protections",
				ElementType:         types.StringType,
				Optional:            true,
			},
			"subnets": schema.SingleNestedAttribute{
				MarkdownDescription: accessControlsModel.Schema().MarkdownDescription,
				Attributes:          accessControlsModel.Schema().Attributes,
				Required:            true,
			},
		},
	}
}

func (*NetworkControlsModel) FromAPI(ctx context.Context, a api.NetworkControls) (NetworkControlsModel, diag.Diagnostics) {
	var accessControlsModel AccessControlsModel
	var diagnostics diag.Diagnostics
	var effect Effect
	return NetworkControlsModel{
		AdvancedProtectionEffect: effect.FromAPI(a.AdvancedProtectionEffect),
		CountriesAccess: func() AccessControlsModel {
			m, d := accessControlsModel.FromAPI(ctx, a.CountriesAccess)
			diagnostics.Append(d...)
			return m
		}(),
		ExceptionSubnets: func() types.List {
			l, d := types.ListValueFrom(ctx, types.StringType, a.ExceptionSubnets)
			diagnostics.Append(d...)
			return l
		}(),
		Subnets: func() AccessControlsModel {
			m, d := accessControlsModel.FromAPI(ctx, a.SubnetsAccess)
			diagnostics.Append(d...)
			return m
		}(),
	}, diagnostics
}

func (n *NetworkControlsModel) ToAPI(ctx context.Context) (api.NetworkControls, diag.Diagnostics) {
	var diagnostics diag.Diagnostics
	strings := func(list types.List) []string {
		strings := make([]string, 0, len(list.Elements()))
		diagnostics.Append(list.ElementsAs(ctx, &strings, false)...)
		return strings
	}
	var effect Effect
	return api.NetworkControls{
		AdvancedProtectionEffect: effect.ToAPI(n.AdvancedProtectionEffect),
		CountriesAccess: func() api.AccessControls {
			c, d := n.CountriesAccess.ToAPI(ctx)
			diagnostics.Append(d...)
			return c
		}(),
		ExceptionSubnets: strings(n.ExceptionSubnets),
		SubnetsAccess: func() api.AccessControls {
			s, d := n.Subnets.ToAPI(ctx)
			diagnostics.Append(d...)
			return s
		}(),
	}, diagnostics
}

type AccessControlsModel struct {
	Alert          types.List   `tfsdk:"alert"`
	Allow          types.List   `tfsdk:"allow"`
	AllowMode      types.Bool   `tfsdk:"allow_mode"`
	Enabled        types.Bool   `tfsdk:"enabled"`
	FallbackEffect types.String `tfsdk:"fallback_effect"`
	Prevent        types.List   `tfsdk:"prevent"`
}

func (*AccessControlsModel) Schema() schema.Schema {
	var effect Effect
	return schema.Schema{
		MarkdownDescription: "AccessControls contains the access controls config (e.g., denied/allowed sources)",
		Attributes: map[string]schema.Attribute{
			"alert": schema.ListAttribute{
				MarkdownDescription: "Alert lists the denied sources for which alerts are generated",
				ElementType:         types.StringType,
				Optional:            true,
			},
			"allow": schema.ListAttribute{
				MarkdownDescription: "Allow lists the allowed sources",
				ElementType:         types.StringType,
				Optional:            true,
			},
			"allow_mode": schema.BoolAttribute{
				MarkdownDescription: "AllowMode indicates allowlist (true) or denylist (false) mode",
				Optional:            true,
			},
			"enabled": schema.BoolAttribute{
				MarkdownDescription: "Enabled indicates if access controls protection is enabled",
				Required:            true,
			},
			"fallback_effect": effect.Attribute(),
			"prevent": schema.ListAttribute{
				MarkdownDescription: "Prevent lists the denied sources",
				ElementType:         types.StringType,
				Optional:            true,
			},
		},
	}
}

func (*AccessControlsModel) FromAPI(ctx context.Context, a api.AccessControls) (AccessControlsModel, diag.Diagnostics) {
	var diagnostics diag.Diagnostics
	var effect Effect
	return AccessControlsModel{
		Alert: func() types.List {
			l, d := types.ListValueFrom(ctx, types.StringType, a.Alert)
			diagnostics.Append(d...)
			return l
		}(),
		Allow: func() types.List {
			l, d := types.ListValueFrom(ctx, types.StringType, a.Allow)
			diagnostics.Append(d...)
			return l
		}(),
		AllowMode:      types.BoolValue(a.AllowMode),
		Enabled:        types.BoolValue(a.Enabled),
		FallbackEffect: effect.FromAPI(a.FallbackEffect),
		Prevent: func() types.List {
			l, d := types.ListValueFrom(ctx, types.StringType, a.Prevent)
			diagnostics.Append(d...)
			return l
		}(),
	}, diagnostics
}

func (a *AccessControlsModel) ToAPI(ctx context.Context) (api.AccessControls, diag.Diagnostics) {
	var diagnostics diag.Diagnostics
	strings := func(list types.List) []string {
		strings := make([]string, 0, len(list.Elements()))
		diagnostics.Append(list.ElementsAs(ctx, &strings, false)...)
		return strings
	}
	var effect Effect
	return api.AccessControls{
		Alert:          strings(a.Alert),
		Allow:          strings(a.Allow),
		AllowMode:      a.AllowMode.ValueBool(),
		Enabled:        a.Enabled.ValueBool(),
		FallbackEffect: effect.ToAPI(a.FallbackEffect),
		Prevent:        strings(a.Prevent),
	}, diagnostics
}

type RemoteHostForwardingModel struct {
	Enabled types.Bool   `tfsdk:"enabled"`
	Target  types.String `tfsdk:"target"`
}

func (*RemoteHostForwardingModel) Schema() schema.Schema {
	return schema.Schema{
		MarkdownDescription: "RemoteHostForwardingConfig defines a remote host to forward requests to",
		Attributes: map[string]schema.Attribute{
			"enabled": schema.BoolAttribute{
				Computed:            true,
				Default:             booldefault.StaticBool(false),
				MarkdownDescription: "Indicates if remote host forwarding is enabled",
				Optional:            true,
			},
			"target": schema.StringAttribute{
				Computed:            true,
				Default:             stringdefault.StaticString(""),
				MarkdownDescription: "Remote host to forward requests to",
				Optional:            true,
			},
		},
	}
}

func (*RemoteHostForwardingModel) FromAPI(a api.RemoteHostForwarding) RemoteHostForwardingModel {
	return RemoteHostForwardingModel{
		Enabled: types.BoolValue(a.Enabled),
		Target:  types.StringValue(a.Target),
	}
}

func (r *RemoteHostForwardingModel) ToAPI() api.RemoteHostForwarding {
	return api.RemoteHostForwarding{
		Enabled: r.Enabled.ValueBool(),
		Target:  r.Target.ValueString(),
	}
}

type ResponseHeaderSpecsModel struct {
	Name     types.String `tfsdk:"name"`
	Override types.Bool   `tfsdk:"override"`
	Values   types.List   `tfsdk:"values"`
}

func (*ResponseHeaderSpecsModel) Schema() schema.Schema {
	return schema.Schema{
		MarkdownDescription: "Configuration for modifying HTTP response headers",
		Attributes: map[string]schema.Attribute{
			"name": schema.StringAttribute{
				MarkdownDescription: "Header name (will be canonicalized when possible)",
				Required:            true,
			},
			"override": schema.BoolAttribute{
				MarkdownDescription: "Indicates whether to override existing values rather than append",
				Required:            true,
			},
			"values": schema.ListAttribute{
				MarkdownDescription: "New header values",
				ElementType:         types.StringType,
				Required:            true,
			},
		},
	}
}

func (*ResponseHeaderSpecsModel) FromAPI(ctx context.Context, a api.ResponseHeaderSpec) ResponseHeaderSpecsModel {
	var diagnostics diag.Diagnostics
	return ResponseHeaderSpecsModel{
		Name:     types.StringValue(a.Name),
		Override: types.BoolValue(a.Override),
		Values: func() types.List {
			l, d := types.ListValueFrom(ctx, types.StringType, a.Values)
			diagnostics.Append(d...)
			return l
		}(),
	}
}

func (r *ResponseHeaderSpecsModel) ToAPI(ctx context.Context) (api.ResponseHeaderSpec, diag.Diagnostics) {
	var diagnostics diag.Diagnostics
	return api.ResponseHeaderSpec{
		Name:     r.Name.ValueString(),
		Override: r.Override.ValueBool(),
		Values: func() []string {
			strings := make([]string, 0, len(r.Values.Elements()))
			diagnostics.Append(r.Values.ElementsAs(ctx, &strings, false)...)
			return strings
		}(),
	}, diagnostics
}
