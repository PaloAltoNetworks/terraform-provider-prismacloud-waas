package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"testing"
)

func TestNewClient(t *testing.T) {
	integration := os.Getenv("INTEGRATION")
	if integration == "" {
		t.Skip("set INTEGRATION to run this test")
	}

	consoleURL := os.Getenv("PRISMACLOUDCOMPUTE_CONSOLE_URL")
	if consoleURL == "" {
		t.Fatal("environment variable PRISMACLOUDCOMPUTE_CONSOLE_URL must be set")
	}
	apiVersion := os.Getenv("PRISMACLOUDCOMPUTE_API_VERSION")
	if apiVersion == "" {
		t.Fatal("environment variable PRISMACLOUDCOMPUTE_API_VERSION must be set")
	}
	project := os.Getenv("PRISMACLOUDCOMPUTE_PROJECT")
	if project == "" {
		log.Println("environment variable PRISMACLOUDCOMPUTE_PROJECT is not set")
	}
	username := os.Getenv("PRISMACLOUDCOMPUTE_USERNAME")
	if username == "" {
		log.Println("environment variable PRISMACLOUDCOMPUTE_API_VERSION must be set")
	}
	password := os.Getenv("PRISMACLOUDCOMPUTE_PASSWORD")
	if password == "" {
		log.Println("environment variable PRISMACLOUDCOMPUTE_PASSWORD must be set")
	}

	c, err := NewClient(Config{
		APIVersion:           apiVersion,
		ConsoleURL:           consoleURL,
		Password:             password,
		Project:              project,
		Username:             username,
		SkipCertVerification: true,
	}, http.DefaultClient)
	if err != nil {
		t.Error(err)
	}

	t.Run("list_collections", func(t *testing.T) {
		resp, err := c.ListCollections(context.Background(), ListCollectionsRequest{})
		if err != nil {
			t.Error(err)
		}
		b, err := json.MarshalIndent(resp, "", "\t")
		if err != nil {
			t.Error(err)
		}
		fmt.Printf("%s", b)
	})

	var rules []RuleVersion
	t.Run("get_policy", func(t *testing.T) {
		ctx := context.Background()
		resp, err := c.GetPolicy(ctx, GetPolicyRequest{PolicyType: container})
		if err != nil {
			t.Error(err)
		}
		b, err := json.MarshalIndent(resp, "", "\t")
		if err != nil {
			t.Error(err)
		}
		fmt.Printf("%s", b)
		rules, err = c.ListRules(ctx, ListRulesRequest{})
	})

	if len(rules) > 0 {
		t.Run("get_rule", func(t *testing.T) {
			rule := rules[0]
			resp, err := c.GetRule(context.Background(), GetRuleRequest{Name: rule.Name, PolicyType: container})
			if err != nil {
				t.Error(err)
			}
			b, err := json.MarshalIndent(resp, "", "\t")
			if err != nil {
				t.Error(err)
			}
			fmt.Printf("%s", b)
		})
	} else {
		fmt.Println("no rules found for container policy")
	}

}
