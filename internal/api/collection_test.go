package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var unspecifiedType = Collection{
	Name:        "name",
	AccountIDs:  []string{"a"},
	AppIDs:      []string{"b"},
	Clusters:    []string{"c"},
	CodeRepos:   []string{"d"},
	Color:       "green",
	Containers:  []string{"e"},
	Description: "collection",
	Functions:   []string{"f"},
	Hosts:       []string{"h"},
	Images:      []string{"i"},
	Labels:      []string{"j"},
	Namespaces:  []string{"k"},
	// SupportedTypes: NewTypeSet(),
}

var appEmbeddedPolicyType = Collection{
	Name:        "appEmbeddedPolicyType",
	AccountIDs:  []string{"a"},
	AppIDs:      []string{"b"},
	Clusters:    []string{"c"},
	CodeRepos:   []string{"*"},
	Color:       "green",
	Containers:  []string{"e"},
	Description: "usable by appEmbeddedPolicy",
	Functions:   []string{"*"},
	Hosts:       []string{"*"},
	Images:      []string{"i"},
	Labels:      []string{"*"},
	Namespaces:  []string{"*"},
	// SupportedTypes: NewTypeSet(appEmbeddedPolicy),
}

var containerAndAppEmbeddedPolicyType = Collection{
	Name:        "containerAndAppEmbeddedPolicyType",
	AccountIDs:  []string{"*"},
	AppIDs:      []string{"*"},
	Clusters:    []string{"*"},
	CodeRepos:   []string{"*"},
	Color:       "green",
	Containers:  []string{"*"},
	Description: "usable by containerPolicy or appEmbeddedPolicy",
	Functions:   []string{"*"},
	Hosts:       []string{"*"},
	Images:      []string{"i"},
	Labels:      []string{"*"},
	Namespaces:  []string{"*"},
	// SupportedTypes: NewTypeSet(appEmbeddedPolicy, containerPolicy),
}

var containerPolicyType = Collection{
	Name:        "containerPolicyType",
	AccountIDs:  []string{"a"},
	AppIDs:      []string{"*"},
	Clusters:    []string{"c"},
	CodeRepos:   []string{"*"},
	Color:       "green",
	Containers:  []string{"e"},
	Description: "usable by containerPolicy",
	Functions:   []string{"*"},
	Hosts:       []string{"h"},
	Images:      []string{"i"},
	Labels:      []string{"j"},
	Namespaces:  []string{"k"},
	// SupportedTypes: NewTypeSet(containerPolicy),
}

var hostPolicyType = Collection{
	Name:        "hostPolicyType",
	AccountIDs:  []string{"*"},
	AppIDs:      []string{"*"},
	Clusters:    []string{"*"},
	CodeRepos:   []string{"*"},
	Color:       "green",
	Containers:  []string{"*"},
	Description: "usable by hostPolicy",
	Functions:   []string{"*"},
	Hosts:       []string{"h"},
	Images:      []string{"*"},
	Labels:      []string{"*"},
	Namespaces:  []string{"*"},
	// SupportedTypes: NewTypeSet(hostPolicy),
}

var serverlessPolicyType = Collection{
	Name:        "serverlessPolicyType",
	AccountIDs:  []string{"*"},
	AppIDs:      []string{"*"},
	Clusters:    []string{"*"},
	CodeRepos:   []string{"*"},
	Color:       "green",
	Containers:  []string{"*"},
	Description: "usable by hostPolicy",
	Functions:   []string{"i"},
	Hosts:       []string{"*"},
	Images:      []string{"*"},
	Labels:      []string{"*"},
	Namespaces:  []string{"*"},
	//SupportedTypes: NewTypeSet(serverlessPolicy),
}

var allCollections = []Collection{
	unspecifiedType, appEmbeddedPolicyType, containerAndAppEmbeddedPolicyType, containerPolicyType, hostPolicyType, serverlessPolicyType,
}

func withSupportedTypes(collections ...Collection) []Collection {
	for i := range collections {
		collections[i].SupportedTypes = SupportedTypes(collections[i])
	}
	return collections
}

func withSupportedType(collection Collection) Collection {
	collection.SupportedTypes = SupportedTypes(collection)
	return collection
}

func TestClient_ListCollections(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.Equal(t, "/api/vx.x/collections", r.URL.Path)
		enc := json.NewEncoder(w)
		err := enc.Encode(allCollections)
		require.NoError(t, err)
	}))
	defer s.Close()

	c, err := newClient(s)
	assert.NoError(t, err)

	t.Run("all_collections", func(t *testing.T) {
		resp, err := c.ListCollections(context.Background(), ListCollectionsRequest{})
		assert.NoError(t, err)
		assert.Equal(t, withSupportedTypes(allCollections...), resp.Collections)
	})

	t.Run("collection_by_name", func(t *testing.T) {
		t.Run("found", func(t *testing.T) {
			resp, err := c.ListCollections(context.Background(), ListCollectionsRequest{Name: "name"})
			assert.NoError(t, err)
			assert.Equal(t, withSupportedTypes(unspecifiedType), resp.Collections)
		})
		t.Run("no_match", func(t *testing.T) {
			resp, err := c.ListCollections(context.Background(), ListCollectionsRequest{Name: "noname"})
			assert.NoError(t, err)
			assert.Equal(t, []Collection{}, resp.Collections)
		})
	})

	t.Run("collections_by_type", func(t *testing.T) {
		t.Run("appEmbedded", func(t *testing.T) {
			resp, err := c.ListCollections(context.Background(), ListCollectionsRequest{Types: NewTypeSet(appEmbeddedPolicy)})
			assert.NoError(t, err)
			assert.Equal(t, withSupportedTypes(appEmbeddedPolicyType, containerAndAppEmbeddedPolicyType), resp.Collections)
		})
		t.Run("container", func(t *testing.T) {
			resp, err := c.ListCollections(context.Background(), ListCollectionsRequest{Types: NewTypeSet(containerPolicy)})
			assert.NoError(t, err)
			assert.Equal(t, withSupportedTypes(containerAndAppEmbeddedPolicyType, containerPolicyType), resp.Collections)
		})
		t.Run("host", func(t *testing.T) {
			resp, err := c.ListCollections(context.Background(), ListCollectionsRequest{Types: NewTypeSet(hostPolicy)})
			assert.NoError(t, err)
			assert.Equal(t, withSupportedTypes(hostPolicyType), resp.Collections)
		})
		t.Run("host", func(t *testing.T) {
			resp, err := c.ListCollections(context.Background(), ListCollectionsRequest{Types: NewTypeSet(serverlessPolicy)})
			assert.NoError(t, err)
			assert.Equal(t, withSupportedTypes(serverlessPolicyType), resp.Collections)
		})
		t.Run("all", func(t *testing.T) {
			resp, err := c.ListCollections(context.Background(), ListCollectionsRequest{})
			assert.NoError(t, err)
			assert.Equal(t, withSupportedTypes(allCollections...), resp.Collections)
		})
	})
}

func newClient(s *httptest.Server) (Client, error) {
	return NewClient(Config{
		ConsoleURL:         s.URL,
		APIVersion:         "vx.x",
		SkipAuthentication: true,
	}, http.DefaultClient)
}

func TestClient_GetCollection(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.Equal(t, "/api/vx.x/collections", r.URL.Path)
		enc := json.NewEncoder(w)
		err := enc.Encode(allCollections)
		require.NoError(t, err)
	}))
	defer s.Close()

	c, err := newClient(s)
	assert.NoError(t, err)

	t.Run("get_collection", func(t *testing.T) {
		t.Run("for_name", func(t *testing.T) {
			resp, err := c.GetCollection(context.Background(), GetCollectionRequest{Name: "name"})
			require.NoError(t, err)
			assert.Equal(t, withSupportedType(unspecifiedType), resp)
		})
		t.Run("no_name", func(t *testing.T) {
			_, err := c.GetCollection(context.Background(), GetCollectionRequest{})
			require.Error(t, err)
			assert.ErrorIs(t, err, MissingRequiredValue)
		})
		t.Run("not_found", func(t *testing.T) {
			_, err := c.GetCollection(context.Background(), GetCollectionRequest{Name: "noname"})
			require.Error(t, err)
			assert.ErrorIs(t, err, NotFound)
		})
	})
}

func TestClient_CreateCollection(t *testing.T) {
	collections := make([]Collection, len(allCollections))
	copy(collections, allCollections)
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/vx.x/collections", r.URL.Path)
		switch r.Method {
		case "POST":
			var prismaSpec PrismaCollectionSpec
			err := json.NewDecoder(r.Body).Decode(&prismaSpec)
			require.NoError(t, err)
			collections = append(collections, Collection{
				AccountIDs:     prismaSpec.AccountIDs,
				AppIDs:         prismaSpec.AppIDs,
				Clusters:       prismaSpec.Clusters,
				CodeRepos:      prismaSpec.CodeRepos,
				Color:          prismaSpec.Color,
				Containers:     prismaSpec.Containers,
				Description:    prismaSpec.Description,
				Functions:      prismaSpec.Functions,
				Hosts:          prismaSpec.Hosts,
				Images:         prismaSpec.Images,
				Labels:         prismaSpec.Labels,
				Namespaces:     prismaSpec.Namespaces,
				Name:           prismaSpec.Name,
				Owner:          "test",
				Prisma:         false,
				System:         false,
				SupportedTypes: prismaSpec.SupportedTypes(),
			})
			w.WriteHeader(http.StatusOK)
		case "GET":
			enc := json.NewEncoder(w)
			err := enc.Encode(collections)
			require.NoError(t, err)
		default:
			t.Errorf("unhandled method %s", r.Method)
		}
	}))
	defer s.Close()

	c, err := newClient(s)
	assert.NoError(t, err)

	t.Run("create_collection", func(t *testing.T) {
		t.Run("for_name", func(t *testing.T) {
			collection, err := c.CreateCollection(context.Background(),
				CreateCollectionRequest{Name: "for_name", Images: []string{"i"}})
			require.NoError(t, err)
			assert.Equal(t, "for_name", collection.Name)
			assert.Equal(t, []string{"i"}, collection.Images)
		})
		t.Run("no_name", func(t *testing.T) {
			_, err := c.CreateCollection(context.Background(), CreateCollectionRequest{})
			require.Error(t, err)
			assert.ErrorIs(t, err, MissingRequiredValue)
		})
		t.Run("exist_conflict", func(t *testing.T) {
			_, err := c.CreateCollection(context.Background(),
				CreateCollectionRequest{Name: "name", Images: []string{"i"}})
			require.Error(t, err)
			assert.ErrorIs(t, err, ExistConflict)
		})
		t.Run("with_type_ok", func(t *testing.T) {
			collection, err := c.CreateCollection(context.Background(),
				CreateCollectionRequest{Name: "container", Images: []string{"i"}, SupportedTypes: NewTypeSet(containerPolicy)})
			require.NoError(t, err)
			assert.Equal(t, "container", collection.Name)
			assert.Equal(t, []string{"i"}, collection.Images)
			assert.True(t, collection.SupportedTypes.Contains(containerPolicy))
		})
		t.Run("with_container_type_error", func(t *testing.T) {
			_, err := c.CreateCollection(context.Background(),
				CreateCollectionRequest{Name: "not_container", Hosts: []string{"h"}, SupportedTypes: NewTypeSet(containerPolicy)})
			require.Error(t, err)
			assert.ErrorIs(t, err, InvalidValue)
		})
		t.Run("with_host_type_error", func(t *testing.T) {
			_, err := c.CreateCollection(context.Background(),
				CreateCollectionRequest{Name: "not_host", AppIDs: []string{"b"}, SupportedTypes: NewTypeSet(hostPolicy)})
			require.Error(t, err)
			assert.ErrorIs(t, err, InvalidValue)
		})
		t.Run("with_app_embedded_type_error", func(t *testing.T) {
			_, err := c.CreateCollection(context.Background(),
				CreateCollectionRequest{Name: "not_app_embedded", Hosts: []string{"h"}, SupportedTypes: NewTypeSet(appEmbeddedPolicy)})
			require.Error(t, err)
			assert.ErrorIs(t, err, InvalidValue)
		})
		t.Run("with_serverless_type_error", func(t *testing.T) {
			_, err := c.CreateCollection(context.Background(),
				CreateCollectionRequest{Name: "not_serverless", Hosts: []string{"h"}, SupportedTypes: NewTypeSet(serverlessPolicy)})
			require.Error(t, err)
			assert.ErrorIs(t, err, InvalidValue)
		})
	})
}

func TestClient_UpdateCollection(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "PUT":
			assert.Equal(t, "/api/vx.x/collections/name", r.URL.Path)
			w.WriteHeader(http.StatusOK)
		case "GET":
			assert.Equal(t, "/api/vx.x/collections", r.URL.Path)
			_, _ = w.Write([]byte(`[{"name":"name","images":["i"]}]`))
		default:
			t.Errorf("unhandled method %s", r.Method)
		}
	}))
	defer s.Close()

	c, err := newClient(s)
	assert.NoError(t, err)

	t.Run("update_collection", func(t *testing.T) {
		t.Run("for_name", func(t *testing.T) {
			collection, err := c.UpdateCollection(context.Background(), UpdateCollectionRequest{Name: "name", Images: []string{"i"}})
			require.NoError(t, err)
			assert.Equal(t, withSupportedType(Collection{Name: "name", Images: []string{"i"}}), collection)
		})
		t.Run("no_name", func(t *testing.T) {
			_, err := c.UpdateCollection(context.Background(), UpdateCollectionRequest{})
			require.Error(t, err)
			assert.ErrorIs(t, err, MissingRequiredValue)
		})
	})
}

func TestClient_DeleteCollection(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "DELETE", r.Method)
		assert.Regexp(t, `/api/vx.x/collections/(no)?name`, r.URL.Path)
		_, _ = w.Write([]byte("{}"))
	}))
	defer s.Close()

	c, err := newClient(s)
	assert.NoError(t, err)

	t.Run("delete_collection", func(t *testing.T) {
		t.Run("for_name", func(t *testing.T) {
			resp, err := c.DeleteCollection(context.Background(), DeleteCollectionRequest{Name: "name"})
			require.NoError(t, err)
			assert.Equal(t, DeleteCollectionResponse{}, resp)
		})
		t.Run("no_name", func(t *testing.T) {
			_, err := c.DeleteCollection(context.Background(), DeleteCollectionRequest{})
			require.Error(t, err)
			assert.ErrorIs(t, err, MissingRequiredValue)
		})
		t.Run("not_found", func(t *testing.T) {
			resp, err := c.DeleteCollection(context.Background(), DeleteCollectionRequest{Name: "noname"})
			require.NoError(t, err)
			assert.Equal(t, DeleteCollectionResponse{}, resp)
		})
	})
}
