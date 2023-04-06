package provider

import (
	"github.com/PaloAltoNetworks/terraform-provider-prismacloud-waas/internal/api"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type Effect struct{}

func (*Effect) Attribute() schema.Attribute {
	return schema.StringAttribute{
		Computed:            true,
		Default:             stringdefault.StaticString("disable"),
		MarkdownDescription: "Effect is the effect applied when a protection is triggered",
		Optional:            true,
		Validators: []validator.String{
			stringvalidator.OneOf("alert", "ban", "disable", "prevent"),
		},
	}
}

func (*Effect) FromAPI(effect api.Effect) types.String {
	return types.StringValue(effect.String())
}

func (*Effect) ToAPI(s types.String) api.Effect {
	return api.Effect(s.ValueString())
}

func (*Effect) FromString(s string) types.String {
	return types.StringValue(s)
}

type BotEffect struct{}

func (*BotEffect) Attribute() schema.Attribute {
	return schema.StringAttribute{
		Computed:            true,
		Default:             stringdefault.StaticString("disable"),
		MarkdownDescription: "Effect is the effect applied when a Bot Protection is triggered",
		Optional:            true,
		Validators: []validator.String{
			stringvalidator.OneOf("alert", "allow", "ban", "disable", "prevent", "ReCaptcha"),
		},
	}
}

func (*BotEffect) FromAPI(effect api.Effect) types.String {
	return types.StringValue(effect.String())
}

func (*BotEffect) ToAPI(s types.String) api.Effect {
	return api.Effect(s.ValueString())
}

func (*BotEffect) FromString(s string) types.String {
	return types.StringValue(s)
}

type CustomRuleEffect struct{}

func (*CustomRuleEffect) Attribute() schema.Attribute {
	return schema.StringAttribute{
		Computed:            true,
		Default:             stringdefault.StaticString("disable"),
		MarkdownDescription: "Effect is the effect applied when a Custom Rule is triggered",
		Optional:            true,
		Validators: []validator.String{
			stringvalidator.OneOf("alert", "allow", "ban", "disable", "prevent"),
		},
	}
}

func (*CustomRuleEffect) FromAPI(effect api.Effect) types.String {
	return types.StringValue(effect.String())
}

func (*CustomRuleEffect) ToAPI(s types.String) api.Effect {
	return api.Effect(s.ValueString())
}

func (*CustomRuleEffect) FromString(s string) types.String {
	return types.StringValue(s)
}

type HeaderSpecEffect struct{}

func (*HeaderSpecEffect) Attribute() schema.Attribute {
	return schema.StringAttribute{
		Computed:            true,
		Default:             stringdefault.StaticString("alert"),
		MarkdownDescription: "For allow flows, effect determines action for non-matching requests. For non-allow flows, effect determines type of action for matching requests",
		Optional:            true,
		Validators: []validator.String{
			stringvalidator.OneOf("alert", "prevent"),
		},
	}
}

func (*HeaderSpecEffect) FromAPI(effect api.Effect) types.String {
	return types.StringValue(effect.String())
}

func (*HeaderSpecEffect) ToAPI(s types.String) api.Effect {
	return api.Effect(s.ValueString())
}

func (*HeaderSpecEffect) FromString(s string) types.String {
	return types.StringValue(s)
}
