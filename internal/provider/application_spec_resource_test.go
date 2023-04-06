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

func TestApplicationSpec_Metadata(t *testing.T) {
	var applicationSpec ApplicationSpec
	var metadata resource.MetadataResponse
	applicationSpec.Metadata(context.Background(), resource.MetadataRequest{}, &metadata)
	assert.Equal(t, "_application_spec", metadata.TypeName)
}

func TestApplicationSpec_Schema(t *testing.T) {
	var applicationSpec ApplicationSpec
	var schema resource.SchemaResponse
	applicationSpec.Schema(context.Background(), resource.SchemaRequest{}, &schema)
	assert.Empty(t, schema.Diagnostics)
	assert.Empty(t, schema.Schema.Validate())
	// shallow check, ensures no unexpected added attributes
	assert.Equal(t, 34, len(schema.Schema.Attributes))
}

func TestApplicationSpec_Configure(t *testing.T) {
	var applicationSpec ApplicationSpec
	ctx := context.Background()
	var config resource.ConfigureResponse
	applicationSpec.Configure(ctx, resource.ConfigureRequest{
		ProviderData: &mockApplicationSpecClient{},
	}, &config)
	assert.Empty(t, config.Diagnostics)
}

func TestApplicationSpec_Create(t *testing.T) {
	var applicationSpec ApplicationSpec
	var schemaResponse resource.SchemaResponse
	applicationSpec.Schema(context.Background(), resource.SchemaRequest{}, &schemaResponse)
	if schemaResponse.Diagnostics.HasError() {
		t.Fatalf("%+v", schemaResponse.Diagnostics)
	}
	plan := tfsdk.Plan{Schema: schemaResponse.Schema}
	planApplicationSpec := newApplicationSpecModel(t)
	diags := plan.Set(context.Background(), planApplicationSpec)
	if diags.HasError() {
		t.Fatalf("%+v", diags)
	}

	var m mockApplicationSpecClient
	defer m.AssertExpectations(t)
	call := m.On(
		"CreateApplicationSpec",
		mock.MatchedBy(func(r api.CreateApplicationSpecRequest) bool {
			expected := createApplicationSpecRequest(t, r.ApplicationSpec)
			return assert.Equal(t, expected, r)
		}),
	)
	call.RunFn = func(args mock.Arguments) {
		createRequest := args.Get(0).(api.CreateApplicationSpecRequest)
		expected := createApplicationSpecRequest(t, createRequest.ApplicationSpec)
		call.Return(api.ApplicationSpecVersion{
			ApplicationSpec: expected.ApplicationSpec,
			Version:         expected.Version(),
		}, nil)
	}

	c := &ApplicationSpec{client: &m}
	ctx := context.Background()
	var resp resource.CreateResponse
	c.Create(ctx, resource.CreateRequest{Plan: plan}, &resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("%+v", resp.Diagnostics)
	}
	var created ApplicationSpecModel
	diags = resp.State.Get(ctx, &created)
	if diags.HasError() {
		t.Fatalf("%+v", diags)
	}
	assert.Empty(t, planApplicationSpec.Version)
	planApplicationSpec.Version = created.Version
	assert.Equal(t, planApplicationSpec, created)
}

func TestApplicationSpec_Read(t *testing.T) {
	var applicationSpec ApplicationSpec
	var schemaResponse resource.SchemaResponse
	applicationSpec.Schema(context.Background(), resource.SchemaRequest{}, &schemaResponse)
	if schemaResponse.Diagnostics.HasError() {
		t.Fatalf("%+v", schemaResponse.Diagnostics)
	}
	state := tfsdk.State{Schema: schemaResponse.Schema}
	stateApplicationSpec := newApplicationSpecModel(t)
	diags := state.Set(context.Background(), stateApplicationSpec)
	if diags.HasError() {
		t.Fatalf("%+v", diags)
	}

	var m mockApplicationSpecClient
	defer m.AssertExpectations(t)
	apiApplicationSpec := newAPIApplicationSpec(t)
	m.On(
		"GetApplicationSpec",
		api.GetApplicationSpecRequest{AppID: "app-000A"},
	).Return(api.ApplicationSpecVersion{
		ApplicationSpec: apiApplicationSpec,
		Version:         apiApplicationSpec.Version(),
	}, nil)

	c := &ApplicationSpec{client: &m}
	var resp resource.ReadResponse
	ctx := context.Background()
	c.Read(ctx, resource.ReadRequest{
		State: state,
	}, &resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("%+v", resp.Diagnostics)
	}
	var read ApplicationSpecModel
	diags = resp.State.Get(ctx, &read)
	if diags.HasError() {
		t.Fatalf("%+v", diags)
	}
	assert.Empty(t, stateApplicationSpec.Version)
	stateApplicationSpec.Version = read.Version // Version
	assert.Equal(t, stateApplicationSpec, read)
}

func TestApplicationSpec_Update(t *testing.T) {
	updateApplicationSpec := newAPIApplicationSpec(t)
	version := updateApplicationSpec.Version() // TODO; important that version is previousVersion ... rename?
	updateApplicationSpec.XSS.Effect = api.EffectPrevent

	var applicationSpec ApplicationSpec
	var schemaResponse resource.SchemaResponse
	applicationSpec.Schema(context.Background(), resource.SchemaRequest{}, &schemaResponse)
	if schemaResponse.Diagnostics.HasError() {
		t.Fatalf("%+v", schemaResponse.Diagnostics)
	}

	state := tfsdk.State{Schema: schemaResponse.Schema}
	stateApplicationSpec := newApplicationSpecModel(t, func(spec *ApplicationSpecModel) {
		spec.Version = types.StringValue(version)
	})
	diags := state.Set(context.Background(), stateApplicationSpec)
	if diags.HasError() {
		t.Fatalf("%+v", diags)
	}

	plan := tfsdk.Plan{Schema: schemaResponse.Schema}
	planApplicationSpec := newApplicationSpecModel(t)
	var effect Effect
	planApplicationSpec.XSS.Effect = effect.FromString("prevent")
	diags = plan.Set(context.Background(), planApplicationSpec)
	if diags.HasError() {
		t.Fatalf("%+v", diags)
	}

	var m mockApplicationSpecClient
	defer m.AssertExpectations(t)
	apiApplicationSpec := newAPIApplicationSpec(t)
	apiApplicationSpec.XSS.Effect = api.EffectPrevent
	m.On(
		"UpdateApplicationSpec",
		api.UpdateApplicationSpecRequest{
			ApplicationSpecVersion: api.ApplicationSpecVersion{
				ApplicationSpec: updateApplicationSpec,
				Version:         version,
			},
		},
	).Return(api.ApplicationSpecVersion{
		ApplicationSpec: apiApplicationSpec,
		Version:         apiApplicationSpec.Version(),
	}, nil)

	c := &ApplicationSpec{client: &m}
	var resp resource.UpdateResponse
	ctx := context.Background()
	c.Update(ctx, resource.UpdateRequest{
		State: state,
		Plan:  plan,
	}, &resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("%+v", resp.Diagnostics)
	}
	var read ApplicationSpecModel
	diags = resp.State.Get(ctx, &read)
	if diags.HasError() {
		t.Fatalf("%+v", diags)
	}
	planApplicationSpec.Version = read.Version // Version
	assert.Equal(t, planApplicationSpec, read)
}

func TestApplicationSpec_Delete(t *testing.T) {
	deleteApplicationSpec := newAPIApplicationSpec(t)
	version := deleteApplicationSpec.Version()

	var applicationSpec ApplicationSpec
	var schemaResponse resource.SchemaResponse
	applicationSpec.Schema(context.Background(), resource.SchemaRequest{}, &schemaResponse)
	if schemaResponse.Diagnostics.HasError() {
		t.Fatalf("%+v", schemaResponse.Diagnostics)
	}

	state := tfsdk.State{Schema: schemaResponse.Schema}
	stateApplicationSpec := newApplicationSpecModel(t, func(spec *ApplicationSpecModel) {
		spec.Version = types.StringValue(version)
	})
	diags := state.Set(context.Background(), stateApplicationSpec)
	if diags.HasError() {
		t.Fatalf("%+v", diags)
	}

	var m mockApplicationSpecClient
	defer m.AssertExpectations(t)

	m.On(
		"DeleteApplicationSpec",
		api.DeleteApplicationSpecRequest{
			AppID:   deleteApplicationSpec.AppID,
			Version: version,
		},
	).Return(api.DeleteApplicationSpecResponse{}, nil)

	c := &ApplicationSpec{client: &m}
	var resp resource.DeleteResponse
	ctx := context.Background()
	c.Delete(ctx, resource.DeleteRequest{
		State: state,
	}, &resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("%+v", resp.Diagnostics)
	}
	assert.Empty(t, resp.State)
}

func TestApplicationSpec_ImportState(t *testing.T) {
	var applicationSpec ApplicationSpec
	var schemaResponse resource.SchemaResponse
	ctx := context.Background()
	applicationSpec.Schema(ctx, resource.SchemaRequest{}, &schemaResponse)
	if schemaResponse.Diagnostics.HasError() {
		t.Fatalf("%+v", schemaResponse.Diagnostics)
	}
	state := tfsdk.State{Schema: schemaResponse.Schema}
	stateApplicationSpec := newApplicationSpecModel(t)
	diags := state.Set(ctx, stateApplicationSpec)
	if diags.HasError() {
		t.Fatalf("%+v", diags)
	}

	var m mockApplicationSpecClient
	defer m.AssertExpectations(t)
	apiApplicationSpec := newAPIApplicationSpec(t)
	m.On(
		"GetApplicationSpec",
		api.GetApplicationSpecRequest{AppID: "app-000A"},
	).Return(api.ApplicationSpecVersion{
		ApplicationSpec: apiApplicationSpec,
		Version:         apiApplicationSpec.Version(),
	}, nil)

	a := &ApplicationSpec{client: &m}
	var resp resource.ImportStateResponse
	a.ImportState(ctx, resource.ImportStateRequest{
		ID: "app-000A",
	}, &resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("%+v", resp.Diagnostics)
	}
	var read ApplicationSpecModel
	diags = resp.State.Get(ctx, &read)
	if diags.HasError() {
		t.Fatalf("%+v", diags)
	}
	assert.Empty(t, stateApplicationSpec.Version)
	stateApplicationSpec.Version = read.Version // Version
	assert.Equal(t, stateApplicationSpec, read)
}

var _ ApplicationSpecClient = &mockApplicationSpecClient{}

type mockApplicationSpecClient struct {
	mock.Mock
}

func (m *mockApplicationSpecClient) CreateApplicationSpec(_ context.Context, req api.CreateApplicationSpecRequest) (api.ApplicationSpecVersion, error) {
	args := m.Called(req)
	resp := args.Get(0).(api.ApplicationSpecVersion)
	return resp, args.Error(1)
}

func (m *mockApplicationSpecClient) GetApplicationSpec(_ context.Context, req api.GetApplicationSpecRequest) (api.ApplicationSpecVersion, error) {
	args := m.Called(req)
	resp := args.Get(0).(api.ApplicationSpecVersion)
	return resp, args.Error(1)
}

func (m *mockApplicationSpecClient) ListApplicationSpecs(_ context.Context, req api.ListApplicationSpecsRequest) (api.ListApplicationSpecsResponse, error) {
	args := m.Called(req)
	resp := args.Get(0).(api.ListApplicationSpecsResponse)
	return resp, args.Error(1)
}

func (m *mockApplicationSpecClient) UpdateApplicationSpec(_ context.Context, req api.UpdateApplicationSpecRequest) (api.ApplicationSpecVersion, error) {
	args := m.Called(req)
	resp := args.Get(0).(api.ApplicationSpecVersion)
	return resp, args.Error(1)
}

func (m *mockApplicationSpecClient) DeleteApplicationSpec(_ context.Context, req api.DeleteApplicationSpecRequest) (api.DeleteApplicationSpecResponse, error) {
	args := m.Called(req)
	resp := args.Get(0).(api.DeleteApplicationSpecResponse)
	return resp, args.Error(1)
}

func newApplicationSpecModel(t *testing.T, options ...func(spec *ApplicationSpecModel)) ApplicationSpecModel {
	t.Helper()
	ctx := context.Background()
	var effect Effect
	var botEffect BotEffect
	var customRuleEffect CustomRuleEffect
	a := ApplicationSpecModel{
		AppID: types.StringValue("app-000A"),
		APISpec: APISpecModel{
			Description: types.StringValue("description"),
			Effect:      effect.FromString("disable"),
			Endpoints: func() types.List {
				var endpointModel EndpointModel
				list, diags := types.ListValueFrom(ctx, endpointModel.Schema().Type(), []EndpointModel{{
					BasePath:     types.StringValue("/basePath"),
					ExposedPort:  types.Int64Value(80),
					GRPC:         types.BoolValue(false),
					Host:         types.StringValue("www.example.com"),
					HTTP2:        types.BoolValue(false),
					InternalPort: types.Int64Value(8080),
					TLS:          types.BoolValue(true),
				}})
				if diags.HasError() {
					t.Fatal(diags.Errors())
				}
				return list
			}(),
			FallbackEffect:           effect.FromString("disable"),
			QueryParamFallbackEffect: effect.FromString("disable"),
			Paths: func() types.Set {
				var pathModel PathModel
				var methodModel MethodModel
				var paramModel ParamModel
				set, diags := types.SetValueFrom(ctx, pathModel.Schema().Type(), []PathModel{{
					Methods: func() types.Set {
						set, diags := types.SetValueFrom(ctx, methodModel.Schema().Type(), []MethodModel{{
							Method: types.StringValue("GET"),
							Parameters: func() types.List {
								list, diags := types.ListValueFrom(ctx, paramModel.Schema().Type(), []ParamModel{{
									AllowEmptyValue: types.BoolValue(false),
									Array:           types.BoolValue(false),
									Explode:         types.BoolValue(false),
									Location:        types.StringValue("header"),
									Max:             types.Float64Value(100),
									Min:             types.Float64Value(1),
									Name:            types.StringValue("name"),
									Required:        types.BoolValue(false),
									Style:           types.StringValue("label"),
									Type:            types.StringValue("string"),
								}})
								if diags.HasError() {
									t.Fatal(diags.Errors())
								}
								return list
							}(),
						}})
						if diags.HasError() {
							t.Fatal(diags.Errors())
						}
						return set
					}(),
					Path: types.StringValue("/path"),
				}})
				if diags.HasError() {
					t.Fatal(diags.Errors())
				}
				return set
			}(),
		},
		AttackTools: ProtectionConfigModel{
			Effect:          effect.FromString("alert"),
			ExceptionFields: exceptionFields(t),
		},
		AutoApplyPatchesSpec: AutoApplyPatchesSpecModel{
			Effect: effect.FromString("alert"),
		},
		BanDurationMinutes: types.Int64Value(5),
		Body: BodyModel{
			InspectionSizeBytes:           types.Int64Value(131072),
			InspectionLimitExceededEffect: effect.FromString("alert"),
			Skip:                          types.BoolValue(false),
		},
		BotProtectionSpec: BotProtectionSpecModel{
			InterstitialPage: types.BoolValue(false),
			JSInjectionSpec: JSInjectionSpecModel{
				Enabled:       types.BoolValue(false),
				TimeoutEffect: botEffect.FromString("disable"),
			},
			KnownBotProtectionsSpec: KnownBotProtectionsSpecModel{
				SearchEngineCrawlers: botEffect.FromString("disable"),
				BusinessAnalytics:    botEffect.FromString("disable"),
				Educational:          botEffect.FromString("disable"),
				News:                 botEffect.FromString("disable"),
				Financial:            botEffect.FromString("disable"),
				ContentFeedClients:   botEffect.FromString("disable"),
				Archiving:            botEffect.FromString("disable"),
				CareerSearch:         botEffect.FromString("disable"),
				MediaSearch:          botEffect.FromString("disable"),
			},
			ReCAPTCHASpec: ReCAPTCHASpecModel{
				AllSessions: types.BoolValue(false),
				Enabled:     types.BoolValue(false),
				SecretKey: SecretModel{
					Encrypted: types.StringValue("encrypted"),
					Plain:     types.StringValue("plain"),
				},
				SiteKey:                types.StringValue("siteKey"),
				SuccessExpirationHours: types.Int64Value(24),
				Type:                   types.StringValue("checkbox"),
			},
			SessionValidation: botEffect.FromString("disable"),
			UnknownBotProtectionSpec: UnknownBotProtectionSpecModel{
				APILibraries:         botEffect.FromString("disable"),
				BotImpersonation:     botEffect.FromString("disable"),
				BrowserImpersonation: botEffect.FromString("disable"),
				Generic:              botEffect.FromString("disable"),
				HTTPLibraries:        botEffect.FromString("disable"),
				RequestAnomalies: RequestAnomaliesModel{
					Effect:    botEffect.FromString("disable"),
					Threshold: types.Int64Value(9),
				},
				WebAutomationTools: botEffect.FromString("disable"),
				WebScrapers:        botEffect.FromString("disable"),
			},
			UserDefinedBots: func() types.List {
				var userDefinedBotModel UserDefinedBotModel
				list, diags := types.ListValueFrom(ctx,
					userDefinedBotModel.Schema().Type(),
					[]UserDefinedBotModel{
						{
							Effect:     botEffect.FromString("block"),
							HeaderName: types.StringValue("headerName"),
							HeaderValues: func() types.List {
								list, diags := types.ListValue(types.StringType, []attr.Value{types.StringValue("headerValue")})
								if diags.HasError() {
									t.Fatal(diags.Errors())
								}
								return list
							}(),
							Name: types.StringValue("name"),
							Subnets: func() types.List {
								list, diags := types.ListValue(types.StringType, []attr.Value{types.StringValue("0.0.0.0/0")})
								if diags.HasError() {
									t.Fatal(diags.Errors())
								}
								return list
							}(),
						},
					})
				if diags.HasError() {
					t.Fatal(diags.Errors())
				}
				return list
			}(),
		},
		ClickjackingEnabled: types.BoolValue(false),
		Certificate: SecretModel{
			Encrypted: types.StringValue("encrypted"),
			Plain:     types.StringValue("plain"),
		},
		CodeInjection: ProtectionConfigModel{
			Effect:          effect.FromString("alert"),
			ExceptionFields: exceptionFields(t),
		},
		CMDi: ProtectionConfigModel{
			Effect:          effect.FromString("alert"),
			ExceptionFields: exceptionFields(t),
		},
		CSRFEnabled: types.BoolValue(true),
		CustomBlockResponseConfig: CustomBlockResponseConfigModel{
			Body:    types.StringValue("body"),
			Code:    types.Int64Value(429),
			Enabled: types.BoolValue(false),
		},
		CustomRules: func() types.List {
			var customRuleModel CustomRuleModel
			list, diags := types.ListValueFrom(ctx, customRuleModel.Schema().Type(), []CustomRuleModel{
				{
					Action: types.StringValue("action"),
					Effect: customRuleEffect.FromString("alert"),
					ID:     types.Int64Value(1),
				},
			})
			if diags.HasError() {
				t.Fatal(diags.Errors())
			}
			return list
		}(),
		DisableEventIDHeader: types.BoolValue(false),
		DoSConfig: DoSConfigModel{
			AlertRates: DoSRatesModel{
				Average: types.Int64Value(5),
				Burst:   types.Int64Value(10),
			},
			BanRates: DoSRatesModel{
				Average: types.Int64Value(50),
				Burst:   types.Int64Value(100),
			},
			Enabled: types.BoolValue(false),
			ExcludedNetworkLists: func() types.List {
				list, diags := types.ListValue(types.StringType, []attr.Value{types.StringValue("excluded")})
				if diags.HasError() {
					t.Fatal(diags.Errors())
				}
				return list
			}(),
			MatchConditions: func() types.List {
				var matchConditionModel MatchConditionModel
				list, diags := types.ListValueFrom(ctx, matchConditionModel.Schema().Type(), []MatchConditionModel{
					{
						FileTypes: func() types.List {
							list, diags := types.ListValue(types.StringType, []attr.Value{types.StringValue(".go")})
							if diags.HasError() {
								t.Fatal(diags.Errors())
							}
							return list
						}(),
						Methods: func() types.List {
							list, diags := types.ListValue(types.StringType, []attr.Value{types.StringValue("POST")})
							if diags.HasError() {
								t.Fatal(diags.Errors())
							}
							return list
						}(),
						ResponseCodeRanges: func() types.List {
							var responseCodeRangesModel ResponseCodeRangesModel
							list, diags := types.ListValueFrom(ctx, responseCodeRangesModel.Schema().Type(), []ResponseCodeRangesModel{{
								End:   types.Int64Value(429),
								Start: types.Int64Value(403),
							}})
							if diags.HasError() {
								t.Fatal(diags.Errors())
							}
							return list
						}(),
					}})
				if diags.HasError() {
					t.Fatal(diags.Errors())
				}
				return list
			}(),
			TrackSession: types.BoolValue(false),
		},
		HeaderSpecs: func() types.List {
			var headerSpecModel HeaderSpecModel
			var headerSpecEffect HeaderSpecEffect
			list, diags := types.ListValueFrom(ctx, headerSpecModel.Schema().Type(), []HeaderSpecModel{{
				Allow:    types.BoolValue(false),
				Effect:   headerSpecEffect.FromString("alert"),
				Name:     types.StringValue("name"),
				Required: types.BoolValue(false),
				Values: func() types.List {
					list, diags := types.ListValue(types.StringType, []attr.Value{types.StringValue("value")})
					if diags.HasError() {
						t.Fatal(diags.Errors())
					}
					return list
				}(),
			}})
			if diags.HasError() {
				t.Fatal(diags.Errors())
			}
			return list
		}(),
		IntelGathering: IntelGatheringModel{
			InfoLeakageEffect:         effect.FromString("alert"),
			RemoveFingerprintsEnabled: types.BoolValue(true),
		},
		LFi: ProtectionConfigModel{
			Effect:          effect.FromString("alert"),
			ExceptionFields: exceptionFields(t),
		},
		MalformedReq: ProtectionConfigModel{
			Effect:          effect.FromString("alert"),
			ExceptionFields: exceptionFields(t),
		},
		MaliciousUpload: MaliciousUploadModel{
			Effect: effect.FromString("alert"),
			AllowedExtensions: func() types.List {
				list, diags := types.ListValue(types.StringType, []attr.Value{
					types.StringValue(".go"),
				})
				if diags.HasError() {
					t.Fatal(diags.Errors())
				}
				return list
			}(),
			AllowedFileTypes: func() types.List {
				list, diags := types.ListValue(types.StringType, []attr.Value{types.StringValue(".go")})
				if diags.HasError() {
					t.Fatal(diags.Errors())
				}
				return list
			}(),
		},
		NetworkControls: NetworkControlsModel{
			AdvancedProtectionEffect: effect.FromString("alert"),
			CountriesAccess: AccessControlsModel{
				Alert: func() types.List {
					l, d := types.ListValue(types.StringType, []attr.Value{types.StringValue("KP")})
					if d.HasError() {
						t.Fatal(d.Errors())
					}
					return l
				}(),
				Allow: func() types.List {
					l, d := types.ListValue(types.StringType, []attr.Value{types.StringValue("UA")})
					if d.HasError() {
						t.Fatal(d.Errors())
					}
					return l
				}(),
				AllowMode:      types.BoolValue(false),
				Enabled:        types.BoolValue(false),
				FallbackEffect: effect.FromString("ban"),
				Prevent: func() types.List {
					l, d := types.ListValue(types.StringType, []attr.Value{types.StringValue("RU")})
					if d.HasError() {
						t.Fatal(d.Errors())
					}
					return l
				}(),
			},
			ExceptionSubnets: func() types.List {
				list, diags := types.ListValue(types.StringType, []attr.Value{types.StringValue("known bad"), types.StringValue("suspicious ips")})
				if diags.HasError() {
					t.Fatal(diags.Errors())
				}
				return list
			}(),
			Subnets: AccessControlsModel{
				Alert: func() types.List {
					l, d := types.ListValue(types.StringType, []attr.Value{types.StringValue("0.0.0.0")})
					if d.HasError() {
						t.Fatal(d.Errors())
					}
					return l
				}(),
				Allow: func() types.List {
					l, d := types.ListValue(types.StringType, []attr.Value{types.StringValue("1.1.1.1")})
					if d.HasError() {
						t.Fatal(d.Errors())
					}
					return l
				}(),
				AllowMode:      types.BoolValue(false),
				Enabled:        types.BoolValue(false),
				FallbackEffect: effect.FromString("ban"),
				Prevent: func() types.List {
					l, d := types.ListValue(types.StringType, []attr.Value{types.StringValue("2.2.2.2")})
					if d.HasError() {
						t.Fatal(d.Errors())
					}
					return l
				}(),
			},
		},
		RemoteHostForwarding: RemoteHostForwardingModel{
			Enabled: types.BoolValue(false),
			Target:  types.StringValue("192.168.1.254"),
		},
		ResponseHeaderSpecs: func() types.List {
			var responseHeaderSpecsModel ResponseHeaderSpecsModel
			list, diags := types.ListValueFrom(ctx, responseHeaderSpecsModel.Schema().Type(), []ResponseHeaderSpecsModel{{
				Name:     types.StringValue("name"),
				Override: types.BoolValue(false),
				Values: func() types.List {
					list, diags := types.ListValue(types.StringType, []attr.Value{types.StringValue("value")})
					if diags.HasError() {
						t.Fatal(diags.Errors())
					}
					return list
				}(),
			}})
			if diags.HasError() {
				t.Fatal(diags.Errors())
			}
			return list
		}(),
		RuleName:              types.StringValue("rule name"),
		SessionCookieBan:      types.BoolValue(false),
		SessionCookieEnabled:  types.BoolValue(false),
		SessionCookieSameSite: types.StringValue("Lax"),
		SessionCookieSecure:   types.BoolValue(false),
		Shellshock: ProtectionConfigModel{
			Effect:          effect.FromString("alert"),
			ExceptionFields: exceptionFields(t),
		},
		SQLi: ProtectionConfigModel{
			Effect:          effect.FromString("alert"),
			ExceptionFields: exceptionFields(t),
		},
		TLSConfig: &TLSConfigModel{
			HSTSConfig: HSTSConfigModel{
				Enabled:           types.BoolValue(false),
				IncludeSubdomains: types.BoolValue(false),
				MaxAgeSeconds:     types.Int64Value(300),
				Preload:           types.BoolValue(false),
			},
			Metadata: &MetadataModel{
				IssuerName:  types.StringValue("issuer name"),
				NotAfter:    types.StringValue("2019-08-24T14:15:22Z"),
				SubjectName: types.StringValue("subject name"),
			},
			MinTLSVersion: types.StringValue("1.3"),
		},
		XSS: ProtectionConfigModel{
			Effect:          effect.FromString("alert"),
			ExceptionFields: exceptionFields(t),
		},
	}
	for _, option := range options {
		option(&a)
	}
	return a
}

func exceptionFields(t *testing.T) types.List {
	t.Helper()
	var exceptionFieldModel ExceptionFieldModel
	list, diags := types.ListValueFrom(context.Background(), exceptionFieldModel.Schema().Type(), []ExceptionFieldModel{{
		Key:      types.StringValue("key"),
		Location: types.StringValue("location"),
	}})
	if diags.HasError() {
		t.Fatal(diags.Errors())
	}
	return list
}

func createApplicationSpecRequest(t *testing.T, a api.ApplicationSpec) api.CreateApplicationSpecRequest {
	t.Helper()

	// In order to ease comparison, compare then replace pointer values via options
	withExpectedPathMethodParameterRange := func(spec *api.ApplicationSpec) {
		min := a.APISpec.Paths[0].Methods[0].Parameters[0].Min
		assert.InDelta(t, 1.0, *min, 0.000001)
		spec.APISpec.Paths[0].Methods[0].Parameters[0].Min = min

		max := a.APISpec.Paths[0].Methods[0].Parameters[0].Max
		assert.InDelta(t, 100.0, *max, 0.000001)
		spec.APISpec.Paths[0].Methods[0].Parameters[0].Max = max
	}

	withExpectedTLSConfig := func(spec *api.ApplicationSpec) {
		expectedMetadata := &api.CertificateMeta{
			IssuerName: "issuer name",
			NotAfter: func() time.Time {
				notAfter, err := time.Parse(time.RFC3339, "2019-08-24T14:15:22Z")
				if err != nil {
					t.Fatal(err)
				}
				return notAfter
			}(),
			SubjectName: "subject name",
		}
		assert.Equal(t, expectedMetadata, spec.TLSConfig.Metadata)
		expectedTLSConfig := &api.TLSConfig{
			HSTSConfig: api.HSTSConfig{
				Enabled:           false,
				MaxAgeSeconds:     300,
				IncludeSubdomains: false,
				Preload:           false,
			},
			Metadata:      spec.TLSConfig.Metadata,
			MinTLSVersion: "1.3",
		}
		assert.Equal(t, expectedTLSConfig, spec.TLSConfig)
		spec.TLSConfig = expectedTLSConfig
	}

	return api.CreateApplicationSpecRequest{ApplicationSpec: newAPIApplicationSpec(t, withExpectedPathMethodParameterRange, withExpectedTLSConfig)}
}

func newAPIApplicationSpec(t *testing.T, options ...func(*api.ApplicationSpec)) api.ApplicationSpec {
	t.Helper()
	a := api.ApplicationSpec{
		APISpec: api.APISpec{
			Description: "description",
			Effect:      "disable",
			Endpoints: []api.Endpoint{{
				BasePath:     "/basePath",
				ExposedPort:  80,
				GRPC:         false,
				Host:         "www.example.com",
				HTTP2:        false,
				InternalPort: 8080,
				TLS:          true,
			}},
			FallbackEffect: "disable",
			Paths: []api.Path{{
				Methods: []api.Method{{
					Name: "GET",
					Parameters: []api.Param{{
						Array:           false,
						AllowEmptyValue: false,
						Explode:         false,
						Location:        "header",
						Name:            "name",
						Max:             func() *float64 { var f float64 = 100; return &f }(),
						Min:             func() *float64 { var f float64 = 1; return &f }(),
						Required:        false,
						Style:           "label",
						Type:            "string",
					}},
				}},
				Name: "/path", // notice this little quirk... Path is Name internally
			}},
			QueryParamFallbackEffect: "disable",
		},
		AppID: "app-000A",
		AttackTools: api.ProtectionConfig{
			Effect: "alert",
			ExceptionFields: []api.ExceptionField{{
				Key:      "key",
				Location: "location",
			}},
		},
		AutoApplyPatchesSpec: api.AutoApplyPatchesSpec{
			Effect: "alert",
		},
		BanDurationMinutes: 5,
		Body: api.BodyConfig{
			InspectionLimitExceededEffect: "alert",
			InspectionSizeBytes:           131072,
			Skip:                          false,
		},
		BotProtectionSpec: api.BotProtectionSpec{
			InterstitialPage: false,
			JSInjectionSpec: api.JSInjectionSpec{
				Enabled:       false,
				TimeoutEffect: "disable",
			},
			KnownBotProtectionsSpec: api.KnownBotProtectionsSpec{
				Archiving:            "disable",
				BusinessAnalytics:    "disable",
				CareerSearch:         "disable",
				ContentFeedClients:   "disable",
				Educational:          "disable",
				Financial:            "disable",
				MediaSearch:          "disable",
				News:                 "disable",
				SearchEngineCrawlers: "disable",
			},
			ReCAPTCHASpec: api.ReCAPTCHASpec{
				AllSessions: false,
				Enabled:     false,
				SecretKey: api.Secret{
					Encrypted: "encrypted",
					Plain:     "plain",
				},
				SiteKey:                "siteKey",
				SuccessExpirationHours: 24,
				Type:                   "checkbox",
			},
			SessionValidation: "disable",
			UnknownBotProtectionSpec: api.UnknownBotProtectionSpec{
				APILibraries:         "disable",
				BotImpersonation:     "disable",
				BrowserImpersonation: "disable",
				Generic:              "disable",
				HTTPLibraries:        "disable",
				RequestAnomalies: api.RequestAnomalies{
					Effect:    "disable",
					Threshold: 9,
				},
				WebAutomationTools: "disable",
				WebScrapers:        "disable",
			},
			UserDefinedBots: []api.UserDefinedBot{{
				Effect:       "block",
				HeaderName:   "headerName",
				HeaderValues: []string{"headerValue"},
				Name:         "name",
				Subnets:      []string{"0.0.0.0/0"},
			}},
		},
		Certificate: api.Secret{
			Encrypted: "encrypted",
			Plain:     "plain",
		},
		CMDi: api.ProtectionConfig{
			Effect: "alert",
			ExceptionFields: []api.ExceptionField{{
				Key:      "key",
				Location: "location",
			}},
		},
		ClickjackingEnabled: false,
		CodeInjection: api.ProtectionConfig{
			Effect: "alert",
			ExceptionFields: []api.ExceptionField{{
				Key:      "key",
				Location: "location",
			}},
		},
		CSRFEnabled: true,
		CustomBlockResponseConfig: api.CustomBlockResponseConfig{
			Body:    "body",
			Code:    429,
			Enabled: false,
		},
		CustomRules: []api.CustomRule{{
			Action: "action",
			Effect: "alert",
			ID:     1,
		}},
		DisableEventIDHeader: false,
		DoSConfig: api.DoSConfig{
			AlertRates: api.DoSRates{
				Average: 5,
				Burst:   10,
			},
			BanRates: api.DoSRates{
				Average: 50,
				Burst:   100,
			},
			Enabled:              false,
			ExcludedNetworkLists: []string{"excluded"},
			MatchConditions: []api.DoSMatchCondition{{
				FileTypes: []string{".go"},
				Methods:   []string{"POST"},
				ResponseCodeRanges: []api.StatusCodeRange{{
					End:   429,
					Start: 403,
				}},
			}},
			TrackSession: false,
		},
		HeaderSpecs: []api.HeaderSpec{{
			Allow:    false,
			Effect:   "alert",
			Name:     "name",
			Required: false,
			Values:   []string{"value"},
		}},
		IntelGathering: api.IntelGathering{
			InfoLeakageEffect:         "alert",
			RemoveFingerprintsEnabled: true,
		},
		LFI: api.ProtectionConfig{
			Effect: "alert",
			ExceptionFields: []api.ExceptionField{{
				Key:      "key",
				Location: "location",
			}},
		},
		MalformedReq: api.ProtectionConfig{
			Effect: "alert",
			ExceptionFields: []api.ExceptionField{{
				Key:      "key",
				Location: "location",
			}},
		},
		MaliciousUpload: api.MaliciousUpload{
			AllowedExtensions: []string{".go"},
			AllowedFileTypes:  []string{".go"},
			Effect:            "alert",
		},
		NetworkControls: api.NetworkControls{
			AdvancedProtectionEffect: "alert",
			CountriesAccess: api.AccessControls{
				Alert:          []string{"KP"},
				Allow:          []string{"UA"},
				AllowMode:      false,
				Enabled:        false,
				FallbackEffect: "ban",
				Prevent:        []string{"RU"},
			},
			ExceptionSubnets: []string{"known bad", "suspicious ips"},
			SubnetsAccess: api.AccessControls{
				Alert:          []string{"0.0.0.0"},
				Allow:          []string{"1.1.1.1"},
				AllowMode:      false,
				Enabled:        false,
				FallbackEffect: "ban",
				Prevent:        []string{"2.2.2.2"},
			},
		},
		RemoteHostForwarding: api.RemoteHostForwarding{
			Enabled: false,
			Target:  "192.168.1.254",
		},
		ResponseHeaderSpecs: []api.ResponseHeaderSpec{{
			Name:     "name",
			Override: false,
			Values:   []string{"value"},
		}},
		RuleName:              "rule name",
		SessionCookieBan:      false,
		SessionCookieEnabled:  false,
		SessionCookieSameSite: "Lax",
		SessionCookieSecure:   false,
		Shellshock: api.ProtectionConfig{
			Effect: "alert",
			ExceptionFields: []api.ExceptionField{{
				Key:      "key",
				Location: "location",
			}},
		},
		SQLi: api.ProtectionConfig{
			Effect: "alert",
			ExceptionFields: []api.ExceptionField{{
				Key:      "key",
				Location: "location",
			}},
		},
		TLSConfig: &api.TLSConfig{
			HSTSConfig: api.HSTSConfig{
				Enabled:           false,
				MaxAgeSeconds:     300,
				IncludeSubdomains: false,
				Preload:           false,
			},
			Metadata: func() *api.CertificateMeta { // Pointer will not shallow Equal - replaced after deep comparison
				return &api.CertificateMeta{
					IssuerName: "issuer name",
					NotAfter: func() time.Time {
						notAfter, err := time.Parse(time.RFC3339, "2019-08-24T14:15:22Z")
						if err != nil {
							panic(err)
						}
						return notAfter
					}(),
					SubjectName: "subject name",
				}
			}(),
			MinTLSVersion: "1.3",
		},
		XSS: api.ProtectionConfig{
			Effect: "alert",
			ExceptionFields: []api.ExceptionField{{
				Key:      "key",
				Location: "location",
			}},
		},
	}
	for _, option := range options {
		option(&a)
	}
	return a
}
