package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/carlmjohnson/requests"
)

func (c *Client) collectionsEndpoint() *requests.Builder {
	return c.apiBuilder.Clone().Pathf("api/%s/collections", c.apiVersion)
}

type Collection struct {
	AccountIDs     []string  `json:"accountIDs"`
	AppIDs         []string  `json:"appIDs"`
	Clusters       []string  `json:"clusters"`
	CodeRepos      []string  `json:"codeRepos"`
	Color          string    `json:"color"`
	Containers     []string  `json:"containers"`
	Description    string    `json:"description"`
	Functions      []string  `json:"functions"`
	Hosts          []string  `json:"hosts"`
	Images         []string  `json:"images"`
	Labels         []string  `json:"labels"`
	Modified       time.Time `json:"modified"`
	Namespaces     []string  `json:"namespaces"`
	Name           string    `json:"name"`
	Owner          string    `json:"owner"`
	Prisma         bool      `json:"prisma"`
	SupportedTypes TypeSet   `json:"supportedTypes"`
	System         bool      `json:"system"`
}

func (c *Collection) UnmarshalJSON(data []byte) error {
	type alias Collection
	aux := &struct {
		*alias
	}{
		alias: (*alias)(c),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	c.SupportedTypes = SupportedTypes(*c)
	return nil
}

func SupportedTypes(c Collection) TypeSet {
	supported := CollectionTypeCriteria{
		AccountIDs: c.AccountIDs,
		AppIDs:     c.AppIDs,
		Clusters:   c.Clusters,
		CodeRepos:  c.CodeRepos,
		Containers: c.Containers,
		Functions:  c.Functions,
		Hosts:      c.Hosts,
		Images:     c.Images,
		Labels:     c.Labels,
		Namespaces: c.Namespaces,
	}.SupportedTypes()
	return supported
}

type CollectionTypeCriteria struct {
	AccountIDs []string
	AppIDs     []string
	Clusters   []string
	CodeRepos  []string
	Containers []string
	Functions  []string
	Hosts      []string
	Images     []string
	Labels     []string
	Namespaces []string
}

type CollectionType string

const (
	appEmbeddedPolicy CollectionType = "appEmbeddedPolicy"
	containerPolicy   CollectionType = "containerPolicy"
	hostPolicy        CollectionType = "hostPolicy"
	serverlessPolicy  CollectionType = "serverlessPolicy"
)

type TypeSet struct {
	m map[CollectionType]struct{}
}

func NewTypeSet(cts ...CollectionType) TypeSet {
	t := &TypeSet{m: make(map[CollectionType]struct{})}
	for _, ct := range cts {
		t.Add(ct)
	}
	return *t
}

func (t *TypeSet) Add(c CollectionType) {
	t.m[c] = struct{}{}
}

func (t *TypeSet) Remove(c CollectionType) {
	delete(t.m, c)
}

func (t *TypeSet) Contains(c CollectionType) bool {
	_, ok := t.m[c]
	return ok
}

func (t *TypeSet) ContainsAll(o TypeSet) bool {
	for ot := range o.m {
		if !t.Contains(ot) {
			return false
		}
	}
	return true
}

func (t *TypeSet) Equals(o TypeSet) bool {
	if len(t.m) != len(o.m) {
		return false
	}
	for ot := range o.m {
		if !t.Contains(ot) {
			return false
		}
	}
	return true
}

func (t *TypeSet) IsEmpty() bool {
	return len(t.m) == 0
}

func (t *TypeSet) Elements() []CollectionType {
	var cts []CollectionType
	for ct := range t.m {
		cts = append(cts, ct)
	}
	sort.Slice(cts, func(i, j int) bool {
		return cts[i] < cts[j]
	})
	return cts
}

func (t *TypeSet) MarshalJSON() ([]byte, error) {
	return json.Marshal(t.Elements())
}

func (t *TypeSet) UnmarshalJSON(data []byte) error {
	var cts []CollectionType
	if err := json.Unmarshal(data, &cts); err != nil {
		return err
	}
	n := NewTypeSet()
	for _, ct := range cts {
		n.Add(ct)
	}
	*t = n
	return nil
}

func (c CollectionTypeCriteria) SupportedTypes() TypeSet {
	const all = "*"
	emptyOrAll := func(s []string) bool {
		return len(s) == 0 || s[0] == all || s[0] == ""
	}
	t := NewTypeSet()
	if emptyOrAll(c.CodeRepos) && emptyOrAll(c.Functions) &&
		emptyOrAll(c.Hosts) && emptyOrAll(c.Labels) && emptyOrAll(c.Namespaces) {
		t.Add(appEmbeddedPolicy) // Allows AppIDs, AccountIDs, Clusters, Images
	}
	if !emptyOrAll(c.Images) && emptyOrAll(c.AppIDs) && emptyOrAll(c.CodeRepos) &&
		emptyOrAll(c.Functions) {
		t.Add(containerPolicy) // Requires Image, allows AccountIDs, Clusters. Containers, Hosts, Labels, Namespaces,
	}
	if emptyOrAll(c.AccountIDs) && emptyOrAll(c.AppIDs) && emptyOrAll(c.Clusters) &&
		emptyOrAll(c.CodeRepos) && emptyOrAll(c.Containers) && emptyOrAll(c.Functions) &&
		emptyOrAll(c.Images) && emptyOrAll(c.Labels) && emptyOrAll(c.Namespaces) {
		t.Add(hostPolicy) // Allows Hosts
	}
	if !emptyOrAll(c.Functions) && emptyOrAll(c.AccountIDs) && emptyOrAll(c.AppIDs) &&
		emptyOrAll(c.Clusters) && emptyOrAll(c.CodeRepos) && emptyOrAll(c.Containers) &&
		emptyOrAll(c.Hosts) && emptyOrAll(c.Namespaces) {
		t.Add(serverlessPolicy) // Allows Functions and Labels
	}
	return t
}

func (c CollectionTypeCriteria) ValidFor(t CollectionType) error {
	if t == "" {
		return nil
	}
	ct := c.SupportedTypes()
	if !ct.Contains(t) {
		switch t {
		case appEmbeddedPolicy:
			return fmt.Errorf("%w: appEmbeddedPolicy only allows: accountIDs, appIDs, clusters and images", InvalidValue)
		case containerPolicy:
			return fmt.Errorf("%w: containerPolicy requires: image, allows: accountIDs, clusters containers, hosts, labels and namespaces", InvalidValue)
		case hostPolicy:
			return fmt.Errorf("%w: hostPolicy only allows hosts", InvalidValue)
		case serverlessPolicy:
			return fmt.Errorf("%w: serverlessPolicy only allows functions and labels", InvalidValue)
		default:
			return fmt.Errorf("%w: unsupported collection type (%q)", InvalidValue, t)
		}
	}
	return nil
}

type ListCollectionsRequest struct {
	Name          string  `json:"name"`
	Types         TypeSet `json:"types"`
	ExcludePrisma bool    `json:"excludePrisma"`
}

func (l ListCollectionsRequest) Filtered() bool {
	return l.Name != "" || !l.Types.IsEmpty()
}

type ListCollectionsResponse struct {
	Collections []Collection
}

func (c *Client) ListCollections(ctx context.Context, req ListCollectionsRequest) (ListCollectionsResponse, error) {
	nameFilter := func(s string) bool {
		if req.Name == "" {
			return true
		}
		return s == req.Name
	}
	typeFilter := func(c Collection) bool {
		if req.Types.IsEmpty() {
			return true
		}
		for _, cts := range req.Types.Elements() {
			if c.SupportedTypes.Contains(cts) {
				return true
			}
		}
		return false
	}

	var collections []Collection
	b := c.collectionsEndpoint().ToJSON(&collections)
	if req.ExcludePrisma {
		b.Param("excludePrisma", "true")
	}
	err := b.Fetch(ctx)
	if err != nil {
		return ListCollectionsResponse{}, fmt.Errorf("list collections: %w", err)
	}
	//for i := range collections {
	//	collections[i].SupportedTypes = SupportedTypes(collections[i])
	//}
	if req.Filtered() {
		filteredCollections := make([]Collection, 0, 1)
		for _, col := range collections {
			if nameFilter(col.Name) && typeFilter(col) {
				filteredCollections = append(filteredCollections, col)
			}
		}
		return ListCollectionsResponse{filteredCollections}, nil
	}
	return ListCollectionsResponse{collections}, nil
}

type GetCollectionRequest struct {
	Name string
}

func (c *Client) GetCollection(ctx context.Context, req GetCollectionRequest) (Collection, error) {
	if req.Name == "" {
		return Collection{}, fmt.Errorf("%w: name", MissingRequiredValue)
	}
	resp, err := c.ListCollections(ctx, ListCollectionsRequest{Name: req.Name})
	if err != nil {
		return Collection{}, fmt.Errorf("get collection: %w", err)
	}
	switch len(resp.Collections) {
	case 0:
		return Collection{}, fmt.Errorf("%w: collection with name=%s", NotFound, req.Name)
	case 1:
		return resp.Collections[0], nil
	default:
		return Collection{}, fmt.Errorf("too many: multiple collections with name=%s", req.Name)
	}
}

type CreateCollectionRequest struct {
	AccountIDs     []string `json:"accountIDs"`
	AppIDs         []string `json:"appIDs"`
	Clusters       []string `json:"clusters"`
	CodeRepos      []string `json:"codeRepos"`
	Color          string   `json:"color"`
	Containers     []string `json:"containers"`
	Description    string   `json:"description"`
	Functions      []string `json:"functions"`
	Hosts          []string `json:"hosts"`
	Images         []string `json:"images"`
	Labels         []string `json:"labels"`
	Name           string   `json:"name"`
	Namespaces     []string `json:"namespaces"`
	SupportedTypes TypeSet  `json:"supportedTypes"`
}

func (c CreateCollectionRequest) TypeCriteria() CollectionTypeCriteria {
	return CollectionTypeCriteria{
		AccountIDs: c.AccountIDs,
		AppIDs:     c.AppIDs,
		Clusters:   c.Clusters,
		CodeRepos:  c.CodeRepos,
		Containers: c.Containers,
		Functions:  c.Functions,
		Hosts:      c.Hosts,
		Images:     c.Images,
		Labels:     c.Labels,
		Namespaces: c.Namespaces,
	}
}

func (c CreateCollectionRequest) PrismaCollectionSpec() PrismaCollectionSpec {
	return PrismaCollectionSpec{
		AccountIDs:  c.AccountIDs,
		AppIDs:      c.AppIDs,
		Clusters:    c.Clusters,
		CodeRepos:   c.CodeRepos,
		Color:       c.Color,
		Containers:  c.Containers,
		Description: c.Description,
		Functions:   c.Functions,
		Hosts:       c.Hosts,
		Images:      c.Images,
		Labels:      c.Labels,
		Namespaces:  c.Namespaces,
		Name:        c.Name,
	}
}

type PrismaCollectionSpec struct {
	AccountIDs  []string `json:"accountIDs"`
	AppIDs      []string `json:"appIDs"`
	Clusters    []string `json:"clusters"`
	CodeRepos   []string `json:"codeRepos"`
	Color       string   `json:"color"`
	Containers  []string `json:"containers"`
	Description string   `json:"description"`
	Functions   []string `json:"functions"`
	Hosts       []string `json:"hosts"`
	Images      []string `json:"images"`
	Labels      []string `json:"labels"`
	Name        string   `json:"name"`
	Namespaces  []string `json:"namespaces"`
}

func (p PrismaCollectionSpec) SupportedTypes() TypeSet {
	return CollectionTypeCriteria{
		AccountIDs: p.AccountIDs,
		AppIDs:     p.AppIDs,
		Clusters:   p.Clusters,
		CodeRepos:  p.CodeRepos,
		Containers: p.Containers,
		Functions:  p.Functions,
		Hosts:      p.Hosts,
		Images:     p.Images,
		Labels:     p.Labels,
		Namespaces: p.Namespaces,
	}.SupportedTypes()
}

func (c *Client) CreateCollection(ctx context.Context, req CreateCollectionRequest) (Collection, error) {
	if req.Name == "" {
		return Collection{}, fmt.Errorf("%w: name", MissingRequiredValue)
	}
	if len(req.SupportedTypes.Elements()) != 0 {
		criteria := req.TypeCriteria()
		for _, t := range req.SupportedTypes.Elements() {
			if err := criteria.ValidFor(t); err != nil {
				return Collection{}, fmt.Errorf("create collection: %w", err)
			}
		}
	}
	_, err := c.GetCollection(ctx, GetCollectionRequest{req.Name})
	switch {
	case err == nil:
		return Collection{}, fmt.Errorf("%w: collection names must be unique", ExistConflict)
	case errors.Is(err, NotFound):
	default:
		return Collection{}, err
	}
	err = c.collectionsEndpoint().BodyJSON(req.PrismaCollectionSpec()).Fetch(ctx)
	if err != nil {
		return Collection{}, fmt.Errorf("create collection: %w", err)
	}
	return c.GetCollection(ctx, GetCollectionRequest{Name: req.Name})
}

type UpdateCollectionRequest struct {
	Name           string   `json:"name"`
	AccountIDs     []string `json:"accountIDs"`
	AppIDs         []string `json:"appIDs"`
	Clusters       []string `json:"clusters"`
	CodeRepos      []string `json:"codeRepos"`
	Color          string   `json:"color"`
	Containers     []string `json:"containers"`
	Description    string   `json:"description"`
	Functions      []string `json:"functions"`
	Hosts          []string `json:"hosts"`
	Images         []string `json:"images"`
	Labels         []string `json:"labels"`
	Namespaces     []string `json:"namespaces"`
	SupportedTypes TypeSet  `json:"supportedTypes"`
}

func (u UpdateCollectionRequest) TypeCriteria() CollectionTypeCriteria {
	return CollectionTypeCriteria{
		AccountIDs: u.AccountIDs,
		AppIDs:     u.AppIDs,
		Clusters:   u.Clusters,
		CodeRepos:  u.CodeRepos,
		Containers: u.Containers,
		Functions:  u.Functions,
		Hosts:      u.Hosts,
		Images:     u.Images,
		Labels:     u.Labels,
		Namespaces: u.Namespaces,
	}
}

func (u UpdateCollectionRequest) PrismaCollectionSpec() PrismaCollectionSpec {
	return PrismaCollectionSpec{
		AccountIDs:  u.AccountIDs,
		AppIDs:      u.AppIDs,
		Clusters:    u.Clusters,
		CodeRepos:   u.CodeRepos,
		Color:       u.Color,
		Containers:  u.Containers,
		Description: u.Description,
		Functions:   u.Functions,
		Hosts:       u.Hosts,
		Images:      u.Images,
		Labels:      u.Labels,
		Namespaces:  u.Namespaces,
		Name:        u.Name,
	}
}

func (c *Client) UpdateCollection(ctx context.Context, req UpdateCollectionRequest) (Collection, error) {
	if req.Name == "" {
		return Collection{}, fmt.Errorf("%w: name", MissingRequiredValue)
	}
	if len(req.SupportedTypes.Elements()) != 0 {
		criteria := req.TypeCriteria()
		for _, t := range req.SupportedTypes.Elements() {
			if err := criteria.ValidFor(t); err != nil {
				return Collection{}, fmt.Errorf("create collection: %w", err)
			}
		}
	}
	// because the API endpoints are degenerate and don't support a trailing slash, we have to re-supply the `collections` path element
	err := c.collectionsEndpoint().Pathf("./collections/%s", req.Name).BodyJSON(req).Put().Fetch(ctx)
	if err != nil {
		return Collection{}, fmt.Errorf("update collection: %w", err)
	}
	return c.GetCollection(ctx, GetCollectionRequest{Name: req.Name})
}

type DeleteCollectionRequest struct {
	Name string `json:"name"`
}

type DeleteCollectionResponse struct{}

func (c *Client) DeleteCollection(ctx context.Context, req DeleteCollectionRequest) (DeleteCollectionResponse, error) {
	if req.Name == "" {
		return DeleteCollectionResponse{}, fmt.Errorf("%w: name", MissingRequiredValue)
	}
	// because the API endpoints are degenerate and don't support a trailing slash, we have to re-supply the `collections` path element
	err := c.collectionsEndpoint().Pathf("./collections/%s", req.Name).Delete().Fetch(ctx)
	if err != nil {
		return DeleteCollectionResponse{}, fmt.Errorf("delete collection: %w", err)
	}
	return DeleteCollectionResponse{}, nil
}
