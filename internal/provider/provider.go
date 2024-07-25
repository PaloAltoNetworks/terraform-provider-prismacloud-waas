package provider

import (
	"context"
	"log"
	"net/http"
	"os"

	"github.com/PaloAltoNetworks/terraform-provider-prismacloud-waas/internal/api"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var apiVersionDefault = "v1"

// Ensure ScaffoldingProvider satisfies various provider interfaces.
var _ provider.Provider = &Provider{}

// Provider defines the provider implementation.
type Provider struct {
	// version is set to the provider version on release, "dev" when the
	// provider is built and run locally, and "test" when running acceptance tests.
	version string
}

// providerModel describes the provider data model.
type providerModel struct {
	ConsoleURL           types.String `tfsdk:"console_url"`
	APIVersion           types.String `tfsdk:"api_version"`
	Project              types.String `tfsdk:"project"`
	Username             types.String `tfsdk:"username"`
	Password             types.String `tfsdk:"password"`
	SkipCertVerification types.Bool   `tfsdk:"skip_cert_verification"`
	ConfigFile           types.String `tfsdk:"config_file"`
}

func (p *Provider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "prismacloud-waas"
	resp.Version = p.version
}

func (p *Provider) Schema(_ context.Context, _ provider.SchemaRequest, response *provider.SchemaResponse) {
	response.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"console_url": schema.StringAttribute{
				MarkdownDescription: "URL of the Prisma Cloud Console",
				Required:            true,
			},
			"api_version": schema.StringAttribute{
				MarkdownDescription: "Version of the Prisma Cloud API",
				Optional:            true,
			},
			"project": schema.StringAttribute{
				MarkdownDescription: "Project for multi-tenant environments",
				Optional:            true,
			},
			"username": schema.StringAttribute{
				Description: "Prisma Cloud Compute username",
				Required:    true,
			},
			"password": schema.StringAttribute{
				MarkdownDescription: "Prisma Cloud Compute password",
				Required:            true,
				Sensitive:           true,
			},
			"skip_cert_verification": schema.BoolAttribute{
				MarkdownDescription: "If true, skip certificate verification",
				Optional:            true,
			},
			"config_file": schema.StringAttribute{
				MarkdownDescription: "Configuration file in JSON format. See examples/creds.json",
				Optional:            true,
			},
		},
	}
}

func (p *Provider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	consoleURL := os.Getenv("PRISMACLOUDCOMPUTE_CONSOLE_URL")
	apiVersion := os.Getenv("PRISMACLOUDCOMPUTE_API_VERSION")
	project := os.Getenv("PRISMACLOUDCOMPUTE_PROJECT")
	username := os.Getenv("PRISMACLOUDCOMPUTE_USERNAME")
	password := os.Getenv("PRISMACLOUDCOMPUTE_PASSWORD")
	// configFile := os.Getenv("PRISMACLOUDCOMPUTE_CONFIG_FILE")

	var config providerModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	log.Printf("%+v\n", config)

	if config.ConsoleURL.IsUnknown() {
		resp.Diagnostics.AddAttributeError(path.Root("consoleURL"), "Unknown API consoleURL", "The provider cannot create the API client as there is an unknown configuration value for the API consoleURL. "+
			"Either target apply the source of the value first, set the value statically in the configuration, or use the PRISMACLOUDCOMPUTE_CONSOLE_URL environment variable.")
	}
	if config.APIVersion.IsUnknown() || config.APIVersion.IsNull() {
		config.APIVersion = types.StringValue(apiVersionDefault)
	}
	if config.Project.IsUnknown() {
		config.Project = types.StringValue("")
	}
	if config.Username.IsUnknown() {
		resp.Diagnostics.AddAttributeError(path.Root("username"), "Unknown API username", "The provider cannot create the API client as there is an unknown configuration value for the API username. "+
			"Either target apply the source of the value first, set the value statically in the configuration, or use the PRISMACLOUDCOMPUTE_USERNAME environment variable.")
	}
	if config.Password.IsUnknown() {
		resp.Diagnostics.AddAttributeError(path.Root("password"), "Unknown API password", "The provider cannot create the API client as there is an unknown configuration value for the API password. "+
			"Either target apply the source of the value first, set the value statically in the configuration, or use the PRISMACLOUDCOMPUTE_PASSWORD environment variable.")
	}
	if resp.Diagnostics.HasError() {
		return
	}

	if !config.ConsoleURL.IsNull() {
		consoleURL = config.ConsoleURL.ValueString()
	}
	if !config.APIVersion.IsNull() {
		apiVersion = config.APIVersion.ValueString()
	}
	if !config.Project.IsNull() {
		consoleURL = config.Project.ValueString()
	}
	if !config.Username.IsNull() {
		username = config.Username.ValueString()
	}
	if !config.Password.IsNull() {
		password = config.Password.ValueString()
	}

	if consoleURL == "" {
		resp.Diagnostics.AddAttributeError(path.Root("consoleURL"), "Missing API consoleURL", "The provider cannot create the API client as there is a missing or empty value for the API consoleURL. "+
			"Set the console_url value in the configuration or use the PRISMACLOUDCOMPUTE_CONSOLE_URL environment variable. "+
			"If either is already set, ensure the value is not empty.")
	}
	if username == "" {
		resp.Diagnostics.AddAttributeError(path.Root("username"), "Missing API username", "The provider cannot create the API client as there is a missing or empty value for the API username. "+
			"Set the username value in the configuration or use the PRISMACLOUDCOMPUTE_USERNAME environment variable. "+
			"If either is already set, ensure the value is not empty.")
	}
	if password == "" {
		resp.Diagnostics.AddAttributeError(path.Root("password"), "Missing API password", "The provider cannot create the API client as there is a missing or empty value for the API password. "+
			"Set the password value in the configuration or use the PRISMACLOUDCOMPUTE_PASSWORD environment variable. "+
			"If either is already set, ensure the value is not empty.")
	}
	if resp.Diagnostics.HasError() {
		return
	}

	client, err := api.NewClient(api.Config{
		ConsoleURL:           consoleURL,
		APIVersion:           apiVersion,
		Project:              project,
		Username:             username,
		Password:             password,
		SkipCertVerification: false,
		SkipAuthentication:   false,
	}, http.DefaultClient)

	if err != nil {
		resp.Diagnostics.AddError("Unable to Create Prisma Cloud API Client", "An unexpected error occurred when creating the Prisma Cloud API client. "+
			"If the error is not clear, please contact the provider developers.\n\n"+
			"Prisma Cloud Client Error: "+err.Error())
		return
	}
	// Example client configuration for config sources and resources
	resp.DataSourceData = client
	resp.ResourceData = client
}

func (p *Provider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewCollection,
		NewRule,
		NewApplicationSpec,
	}
}

func (p *Provider) DataSources(_ context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{}
}

func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &Provider{
			version: version,
		}
	}
}
