package provider

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/PaloAltoNetworks/terraform-provider-prismacloud-waas/internal/api"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/boolplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/setplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// Ensure provider defined types fully satisfy framework interfaces
var _ resource.Resource = &Collection{}
var _ resource.ResourceWithImportState = &Collection{}

func NewCollection() resource.Resource {
	return &Collection{}
}

// Collection defines the resource implementation.
type Collection struct {
	client CollectionClient
}

type CollectionClient interface {
	CreateCollection(ctx context.Context, req api.CreateCollectionRequest) (api.Collection, error)
	GetCollection(ctx context.Context, req api.GetCollectionRequest) (api.Collection, error)
	UpdateCollection(ctx context.Context, req api.UpdateCollectionRequest) (api.Collection, error)
	DeleteCollection(ctx context.Context, req api.DeleteCollectionRequest) (api.DeleteCollectionResponse, error)
}

// CollectionModel represents Prisma Cloud Collection as a Terraform Resource.
type CollectionModel struct {
	AppIDs         types.List   `tfsdk:"app_ids"`
	AccountIDs     types.List   `tfsdk:"account_ids"`
	Containers     types.List   `tfsdk:"containers"`
	Clusters       types.List   `tfsdk:"clusters"`
	Color          types.String `tfsdk:"color"`
	Description    types.String `tfsdk:"description"`
	Functions      types.List   `tfsdk:"functions"`
	Hosts          types.List   `tfsdk:"hosts"`
	Images         types.List   `tfsdk:"images"`
	Labels         types.List   `tfsdk:"labels"`
	Modified       types.String `tfsdk:"modified"`
	Name           types.String `tfsdk:"name"`
	Namespaces     types.List   `tfsdk:"namespaces"`
	Owner          types.String `tfsdk:"owner"`
	Prisma         types.Bool   `tfsdk:"prisma"`
	RequiredTypes  types.Set    `tfsdk:"required_types"`
	SupportedTypes types.Set    `tfsdk:"supported_types"`
	System         types.Bool   `tfsdk:"system"`
}

func (*CollectionModel) Schema() schema.Schema {
	return schema.Schema{
		MarkdownDescription: "Prisma Cloud Collection resource",
		Attributes: map[string]schema.Attribute{
			"account_ids": schema.ListAttribute{
				ElementType:         types.StringType,
				MarkdownDescription: "List of accountIDs",
				Optional:            true,
			},
			"app_ids": schema.ListAttribute{
				ElementType:         types.StringType,
				MarkdownDescription: "List of appIDs",
				Optional:            true,
			},
			"clusters": schema.ListAttribute{
				ElementType:         types.StringType,
				MarkdownDescription: "List of Kubernetes clusters",
				Optional:            true,
			},
			"color": schema.StringAttribute{
				Computed:            true,
				Default:             stringdefault.StaticString("#000000"),
				MarkdownDescription: "Color code for the collection",
				Optional:            true,
			},
			"containers": schema.ListAttribute{
				ElementType:         types.StringType,
				MarkdownDescription: "List of containers",
				Optional:            true,
			},
			"description": schema.StringAttribute{
				Computed:            true,
				Default:             stringdefault.StaticString(""),
				MarkdownDescription: "Free-form text",
				Optional:            true,
			},
			"functions": schema.ListAttribute{
				ElementType:         types.StringType,
				MarkdownDescription: "List of functions",
				Optional:            true,
			},
			"hosts": schema.ListAttribute{
				ElementType:         types.StringType,
				MarkdownDescription: "List of hosts",
				Optional:            true,
			},
			"images": schema.ListAttribute{
				ElementType:         types.StringType,
				MarkdownDescription: "List of images",
				Optional:            true,
			},
			"labels": schema.ListAttribute{
				ElementType:         types.StringType,
				MarkdownDescription: "List of labels",
				Optional:            true,
			},
			"modified": schema.StringAttribute{
				MarkdownDescription: "Datetime when the collection was last modified",
				Computed:            true,
				Optional:            true,
			},
			"name": schema.StringAttribute{
				MarkdownDescription: "Collection name. Must be unique",
				Required:            true,
			},
			"namespaces": schema.ListAttribute{
				ElementType:         types.StringType,
				MarkdownDescription: "List of Kubernetes namespaces",
				Optional:            true,
			},
			"owner": schema.StringAttribute{
				MarkdownDescription: "User who created or last modified the collection",
				Computed:            true,
				Optional:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"prisma": schema.BoolAttribute{
				MarkdownDescription: "Indicates whether this collection originates from Prisma Cloud",
				Computed:            true,
				Optional:            true,
				PlanModifiers: []planmodifier.Bool{
					boolplanmodifier.UseStateForUnknown(),
				},
			},
			"required_types": schema.SetAttribute{
				ElementType:         types.StringType,
				MarkdownDescription: "Indicates the usage types required",
				Required:            true,
			},
			"supported_types": schema.SetAttribute{
				ElementType:         types.StringType,
				MarkdownDescription: "Indicates the possible usage types the collection can support",
				Computed:            true,
				Optional:            true,
				PlanModifiers: []planmodifier.Set{
					setplanmodifier.UseStateForUnknown(),
				},
			},
			"system": schema.BoolAttribute{
				MarkdownDescription: "Indicates whether this collection was created by the system (i.e., a non user) (true) or a real user (false)",
				Computed:            true,
				Optional:            true,
				PlanModifiers: []planmodifier.Bool{
					boolplanmodifier.UseStateForUnknown(),
				},
			},
		},
	}
}

func (r *Collection) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_collection"
}

func (r *Collection) Schema(_ context.Context, _ resource.SchemaRequest, response *resource.SchemaResponse) {
	var collectionModel CollectionModel
	response.Schema = collectionModel.Schema()
}

func (r *Collection) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	client, ok := req.ProviderData.(CollectionClient)
	if !ok {
		resp.Diagnostics.AddError("Unexpected Resource Configure Type", fmt.Sprintf("Expected *api.Client, got: %T. Please report this issue to the provider developers.", req.ProviderData))
		return
	}
	r.client = client
}

func (r *Collection) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan *CollectionModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	m, d := plan.ToAPI(ctx)
	if d.HasError() {
		resp.Diagnostics.Append(diag.NewErrorDiagnostic("mapping to api", "unable to map to api"))
		resp.Diagnostics.Append(d...)
		return
	}

	createReq := api.CreateCollectionRequest{
		AccountIDs:     m.AccountIDs,
		AppIDs:         m.AppIDs,
		Clusters:       m.Clusters,
		Color:          m.Color,
		Containers:     m.Containers,
		Description:    m.Description,
		Functions:      m.Functions,
		Hosts:          m.Hosts,
		Images:         m.Images,
		Labels:         m.Labels,
		Name:           m.Name,
		Namespaces:     m.Namespaces,
		SupportedTypes: m.SupportedTypes,
	}
	created, err := r.client.CreateCollection(ctx, createReq)
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("unable to create Collection %q: %s", plan.Name, err))
		return
	}
	tflog.Trace(ctx, fmt.Sprintf("created Collection resource %s", createReq.Name))

	var collectionModel CollectionModel
	createdState, diags := collectionModel.FromAPI(ctx, created)
	if diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}
	createdState.RequiredTypes = plan.RequiredTypes
	// Save data into Terraform state
	resp.State.Schema = collectionModel.Schema()
	resp.Diagnostics.Append(resp.State.Set(ctx, &createdState)...)
}

func (r *Collection) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state CollectionModel
	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)

	if resp.Diagnostics.HasError() {
		return
	}

	read, err := r.client.GetCollection(ctx, api.GetCollectionRequest{Name: state.Name.ValueString()})
	switch {
	case err == nil:
	case errors.Is(err, api.NotFound):
		// Recreate resource and return
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("unable to read Collection: %s", err))
		return
	}

	var cm CollectionModel
	resp.State.Schema = cm.Schema()
	cm, d := cm.FromAPI(ctx, read)
	if d.HasError() {
		resp.Diagnostics.Append(d...)
		return
	}
	cm.RequiredTypes = state.RequiredTypes

	// Save updated data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &cm)...)
}

func (r *Collection) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan *CollectionModel
	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	c, diags := plan.ToAPI(ctx)
	if diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}
	updateReq := api.UpdateCollectionRequest{
		AccountIDs:     c.AccountIDs,
		AppIDs:         c.AppIDs,
		Clusters:       c.Clusters,
		Color:          c.Color,
		Containers:     c.Containers,
		Description:    c.Description,
		Functions:      c.Functions,
		Hosts:          c.Hosts,
		Images:         c.Images,
		Labels:         c.Labels,
		Namespaces:     c.Namespaces,
		Name:           c.Name,
		SupportedTypes: c.SupportedTypes,
	}
	updated, err := r.client.UpdateCollection(ctx, updateReq)
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("unable to update Collection: %s", err))
		return
	}

	tflog.Trace(ctx, fmt.Sprintf("updated Collection resource %s", updateReq.Name))
	var state CollectionModel
	stateUpdate, diags := state.FromAPI(ctx, updated)
	stateUpdate.RequiredTypes = plan.RequiredTypes
	if diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}
	// Save updated data into Terraform state
	resp.State.Schema = state.Schema()
	resp.Diagnostics.Append(resp.State.Set(ctx, &stateUpdate)...)
}

func (r *Collection) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state CollectionModel
	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	_, err := r.client.DeleteCollection(ctx, api.DeleteCollectionRequest{Name: state.Name.ValueString()})
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Unable to delete Collection with name=%q: %s", state.Name.ValueString(), err.Error()))
		return
	}
}

func (r *Collection) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	read, err := r.client.GetCollection(ctx, api.GetCollectionRequest{Name: req.ID})
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("unable to read ApplicationSpec: %s", err))
		return
	}
	var collectionModel CollectionModel
	state, diags := collectionModel.FromAPI(ctx, read)
	if diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}
	// Save updated data into Terraform state
	resp.State.Schema = collectionModel.Schema()
	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
}

func (*CollectionModel) FromAPI(ctx context.Context, a api.Collection) (CollectionModel, diag.Diagnostics) {
	var diagnostics diag.Diagnostics
	strSliceToList := func(strSlice []string) types.List {
		list, d := types.ListValueFrom(ctx, types.StringType, strSlice)
		diagnostics.Append(d...)
		return list
	}
	return CollectionModel{
		AppIDs:      strSliceToList(a.AppIDs),
		AccountIDs:  strSliceToList(a.AccountIDs),
		Containers:  strSliceToList(a.Containers),
		Clusters:    strSliceToList(a.Clusters),
		Color:       types.StringValue(a.Color),
		Description: types.StringValue(a.Description),
		Functions:   strSliceToList(a.Functions),
		Hosts:       strSliceToList(a.Hosts),
		Images:      strSliceToList(a.Images),
		Labels:      strSliceToList(a.Labels),
		Modified:    types.StringValue(a.Modified.Format(time.RFC3339)),
		Name:        types.StringValue(a.Name),
		Namespaces:  strSliceToList(a.Namespaces),
		Owner:       types.StringValue(a.Owner),
		Prisma:      types.BoolValue(a.Prisma),
		RequiredTypes: func() types.Set {
			s, d := types.SetValueFrom(ctx, types.StringType, []string{})
			diagnostics.Append(d...)
			return s
		}(),
		SupportedTypes: func() types.Set {
			s, d := types.SetValueFrom(ctx, types.StringType, a.SupportedTypes.Elements())
			diagnostics.Append(d...)
			return s
		}(),
		System: types.BoolValue(a.System),
	}, diagnostics
}

func (m *CollectionModel) ToAPI(ctx context.Context) (api.Collection, diag.Diagnostics) {
	var diagnostics diag.Diagnostics
	elemsToStrSlice := func(l types.List) []string {
		strSlice := make([]string, 0, len(l.Elements()))
		d := l.ElementsAs(ctx, &strSlice, false)
		diagnostics.Append(d...)
		return strSlice
	}
	return api.Collection{
		AccountIDs:  elemsToStrSlice(m.AccountIDs),
		AppIDs:      elemsToStrSlice(m.AppIDs),
		Clusters:    elemsToStrSlice(m.Clusters),
		Color:       m.Color.ValueString(),
		Containers:  elemsToStrSlice(m.Containers),
		Description: m.Description.ValueString(),
		Functions:   elemsToStrSlice(m.Functions),
		Hosts:       elemsToStrSlice(m.Hosts),
		Images:      elemsToStrSlice(m.Images),
		Labels:      elemsToStrSlice(m.Labels),
		Name:        m.Name.ValueString(),
		Namespaces:  elemsToStrSlice(m.Namespaces),
		SupportedTypes: func() api.TypeSet {
			if m.SupportedTypes.IsUnknown() {
				return api.NewTypeSet()
			}
			supported := make([]api.CollectionType, 0, len(m.SupportedTypes.Elements()))
			d := m.SupportedTypes.ElementsAs(ctx, &supported, false)
			diagnostics.Append(d...)
			return api.NewTypeSet(supported...)
		}(),
	}, diagnostics
}
