package provider

import (
	"context"
	"testing"
	"time"

	"github.com/PaloAltoNetworks/terraform-provider-prismacloud-waas/internal/api"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestCollectionSpec_Metadata(t *testing.T) {
	var collection Collection
	var metadata resource.MetadataResponse
	collection.Metadata(context.Background(), resource.MetadataRequest{}, &metadata)
	assert.Equal(t, "_collection", metadata.TypeName)
}

func TestCollectionSpec_Schema(t *testing.T) {
	var collection Collection
	var schema resource.SchemaResponse
	ctx := context.Background()
	collection.Schema(ctx, resource.SchemaRequest{}, &schema)
	assert.Empty(t, schema.Diagnostics)
	assert.Empty(t, schema.Schema.ValidateImplementation(ctx))
	// shallow check, ensures no unexpected added attributes
	assert.Equal(t, 18, len(schema.Schema.Attributes))
}

func TestCollectionSpec_Configure(t *testing.T) {
	var collection Collection
	ctx := context.Background()
	var config resource.ConfigureResponse
	collection.Configure(ctx, resource.ConfigureRequest{
		ProviderData: &mockCollectionClient{},
	}, &config)
	assert.Empty(t, config.Diagnostics)
}

func TestCollection_Create(t *testing.T) {
	var collection Collection
	var schemaResponse resource.SchemaResponse
	collection.Schema(context.Background(), resource.SchemaRequest{}, &schemaResponse)
	if schemaResponse.Diagnostics.HasError() {
		t.Fatalf("%+v", schemaResponse.Diagnostics)
	}
	plan := tfsdk.Plan{Schema: schemaResponse.Schema}
	diags := plan.Set(context.Background(), newCollectionModel(t))
	if diags.HasError() {
		t.Fatalf("%+v", diags)
	}

	var m mockCollectionClient
	defer m.AssertExpectations(t)

	newCollection := newAPICollection(t)
	m.On("CreateCollection", api.CreateCollectionRequest{
		Name:           "name",
		AccountIDs:     []string{"*"},
		AppIDs:         []string{"*"},
		Clusters:       []string{"*"},
		Color:          "#00FF00",
		Containers:     []string{"*"},
		Description:    "description",
		Functions:      []string{"*"},
		Hosts:          []string{"*"},
		Images:         []string{"*"},
		Labels:         []string{"*"},
		Namespaces:     []string{"*"},
		SupportedTypes: api.NewTypeSet("containerPolicy"),
	}).Return(newCollection, nil)

	c := &Collection{client: &m}
	ctx := context.Background()
	var resp resource.CreateResponse
	c.Create(ctx, resource.CreateRequest{Plan: plan}, &resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("%+v", resp.Diagnostics)
	}
	var created CollectionModel
	diags = resp.State.Get(ctx, &created)
	if diags.HasError() {
		t.Fatalf("%+v", diags)
	}
	// Add computed values
	expected := newCollectionModel(t, func(cm *CollectionModel) {
		cm.Owner = types.StringValue("test")
		cm.Modified = types.StringValue("0001-01-01T00:00:00Z")
		cm.Prisma = types.BoolValue(false)
		cm.System = types.BoolValue(false)
	})
	assert.Equal(t, expected, created)
}

func TestCollection_Read(t *testing.T) {
	var collection Collection
	var schemaResponse resource.SchemaResponse
	collection.Schema(context.Background(), resource.SchemaRequest{}, &schemaResponse)
	if schemaResponse.Diagnostics.HasError() {
		t.Fatalf("%+v", schemaResponse.Diagnostics)
	}
	state := tfsdk.State{Schema: schemaResponse.Schema}
	diags := state.Set(context.Background(), newCollectionModel(t))
	if diags.HasError() {
		t.Fatalf("%+v", diags)
	}

	var m mockCollectionClient
	defer m.AssertExpectations(t)

	m.On("GetCollection", api.GetCollectionRequest{Name: "name"}).Return(newAPICollection(t), nil)
	c := &Collection{client: &m}
	ctx := context.Background()
	var resp resource.ReadResponse
	c.Read(ctx, resource.ReadRequest{State: state}, &resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("%+v", resp.Diagnostics)
	}
	var current CollectionModel
	diags = resp.State.Get(ctx, &current)
	if diags.HasError() {
		t.Fatalf("%+v", diags)
	}
	// Add computed values
	expected := newCollectionModel(t, func(cm *CollectionModel) {
		cm.Owner = types.StringValue("test")
		cm.Modified = types.StringValue("0001-01-01T00:00:00Z")
		cm.Prisma = types.BoolValue(false)
		cm.System = types.BoolValue(false)
	})
	assert.Equal(t, expected, current)
}

func TestCollection_Update(t *testing.T) {
	var collection Collection
	var schemaResponse resource.SchemaResponse
	collection.Schema(context.Background(), resource.SchemaRequest{}, &schemaResponse)
	if schemaResponse.Diagnostics.HasError() {
		t.Fatalf("%+v", schemaResponse.Diagnostics)
	}
	plan := tfsdk.Plan{Schema: schemaResponse.Schema}
	diags := plan.Set(context.Background(), newCollectionModel(t))
	if diags.HasError() {
		t.Fatalf("%+v", diags)
	}

	var m mockCollectionClient
	defer m.AssertExpectations(t)

	m.On("UpdateCollection", api.UpdateCollectionRequest{
		AccountIDs:     []string{"*"},
		AppIDs:         []string{"*"},
		Clusters:       []string{"*"},
		Color:          "#00FF00",
		Containers:     []string{"*"},
		Description:    "description",
		Functions:      []string{"*"},
		Hosts:          []string{"*"},
		Images:         []string{"*"},
		Labels:         []string{"*"},
		Name:           "name",
		Namespaces:     []string{"*"},
		SupportedTypes: api.NewTypeSet("containerPolicy"),
	}).Return(newAPICollection(t), nil)

	c := &Collection{client: &m}
	ctx := context.Background()
	var resp resource.UpdateResponse
	c.Update(ctx, resource.UpdateRequest{Plan: plan}, &resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("%+v", resp.Diagnostics)
	}
	var updated CollectionModel
	diags = resp.State.Get(ctx, &updated)
	if diags.HasError() {
		t.Fatalf("%+v", diags)
	}
	// Add computed values
	expected := newCollectionModel(t, func(cm *CollectionModel) {
		cm.Owner = types.StringValue("test")
		cm.Modified = types.StringValue("0001-01-01T00:00:00Z")
		cm.Prisma = types.BoolValue(false)
		cm.System = types.BoolValue(false)
	})
	assert.Equal(t, expected, updated)
}

func TestCollection_Delete(t *testing.T) {
	var collection Collection
	var schemaResponse resource.SchemaResponse
	collection.Schema(context.Background(), resource.SchemaRequest{}, &schemaResponse)
	if schemaResponse.Diagnostics.HasError() {
		t.Fatalf("%+v", schemaResponse.Diagnostics)
	}
	state := tfsdk.State{Schema: schemaResponse.Schema}
	diags := state.Set(context.Background(), newCollectionModel(t))
	if diags.HasError() {
		t.Fatalf("%+v", diags)
	}

	var m mockCollectionClient
	defer m.AssertExpectations(t)

	m.On("DeleteCollection", api.DeleteCollectionRequest{
		Name: "name",
	}).Return(api.DeleteCollectionResponse{}, nil)

	c := &Collection{client: &m}
	ctx := context.Background()
	var resp resource.DeleteResponse
	c.Delete(ctx, resource.DeleteRequest{State: state}, &resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("%+v", resp.Diagnostics)
	}
}

func TestCollection_ImportState(t *testing.T) {
	var collection Collection
	var schemaResponse resource.SchemaResponse
	ctx := context.Background()
	collection.Schema(context.Background(), resource.SchemaRequest{}, &schemaResponse)
	if schemaResponse.Diagnostics.HasError() {
		t.Fatalf("%+v", schemaResponse.Diagnostics)
	}
	state := tfsdk.State{Schema: schemaResponse.Schema}
	stateCollection := newCollectionModel(t)
	diags := state.Set(ctx, stateCollection)
	if diags.HasError() {
		t.Fatalf("%+v", diags)
	}

	var m mockCollectionClient
	defer m.AssertExpectations(t)
	apiCollection := newAPICollection(t)
	m.On("GetCollection",
		api.GetCollectionRequest{
			Name: "name",
		},
	).Return(apiCollection, nil)

	c := &Collection{client: &m}
	var resp resource.ImportStateResponse
	c.ImportState(ctx, resource.ImportStateRequest{
		ID: "name",
	}, &resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("%+v", resp.Diagnostics)
	}
	var read CollectionModel
	diags = resp.State.Get(ctx, &read)
	if resp.Diagnostics.HasError() {
		t.Fatalf("%+v", resp.Diagnostics)
	}
	// inject computed values
	stateCollection.Modified = types.StringValue("0001-01-01T00:00:00Z")
	stateCollection.Owner = types.StringValue("test")
	stateCollection.Prisma = types.BoolValue(false)
	stateCollection.System = types.BoolValue(false)
	assert.Equal(t, stateCollection, read)
}

var _ CollectionClient = &mockCollectionClient{}

type mockCollectionClient struct {
	mock.Mock
}

func (m *mockCollectionClient) GetCollection(_ context.Context, req api.GetCollectionRequest) (api.Collection, error) {
	args := m.Called(req)
	resp := args.Get(0).(api.Collection)
	return resp, args.Error(1)
}

func (m *mockCollectionClient) CreateCollection(_ context.Context, req api.CreateCollectionRequest) (api.Collection, error) {
	args := m.Called(req)
	resp := args.Get(0).(api.Collection)
	return resp, args.Error(1)
}

func (m *mockCollectionClient) UpdateCollection(_ context.Context, req api.UpdateCollectionRequest) (api.Collection, error) {
	args := m.Called(req)
	resp := args.Get(0).(api.Collection)
	return resp, args.Error(1)
}

func (m *mockCollectionClient) DeleteCollection(_ context.Context, req api.DeleteCollectionRequest) (api.DeleteCollectionResponse, error) {
	args := m.Called(req)
	resp := args.Get(0).(api.DeleteCollectionResponse)
	return resp, args.Error(1)
}

func newCollectionModel(t *testing.T, opts ...func(cm *CollectionModel)) CollectionModel {
	t.Helper()
	splat := func() types.List {
		return types.ListValueMust(
			types.StringType,
			[]attr.Value{
				types.StringValue("*"),
			},
		)
	}
	cm := CollectionModel{
		AppIDs:      splat(),
		AccountIDs:  splat(),
		Color:       types.StringValue("#00FF00"),
		Clusters:    splat(),
		Containers:  splat(),
		Description: types.StringValue("description"),
		Functions:   splat(),
		Hosts:       splat(),
		Images:      splat(),
		Labels:      splat(),
		Name:        types.StringValue("name"),
		Namespaces:  splat(),
		RequiredTypes: types.SetValueMust(
			types.StringType,
			[]attr.Value{},
		),
		SupportedTypes: func() types.Set {
			return types.SetValueMust(
				types.StringType,
				[]attr.Value{types.StringValue("containerPolicy")},
			)
		}(),
	}
	for _, opt := range opts {
		opt(&cm)
	}
	return cm
}

func newAPICollection(t *testing.T) api.Collection {
	t.Helper()
	return api.Collection{
		Name:        "name",
		AccountIDs:  []string{"*"},
		AppIDs:      []string{"*"},
		Clusters:    []string{"*"},
		Color:       "#00FF00",
		Containers:  []string{"*"},
		Description: "description",
		Functions:   []string{"*"},
		Hosts:       []string{"*"},
		Images:      []string{"*"},
		Labels:      []string{"*"},
		Namespaces:  []string{"*"},
		Owner:       "test",
		Modified: func() time.Time {
			t, err := time.Parse(time.RFC3339, "0001-01-01T00:00:00Z")
			if err != nil {
				panic(err)
			}
			return t
		}(),
		Prisma:         false,
		System:         false,
		SupportedTypes: api.NewTypeSet("containerPolicy"),
	}
}
