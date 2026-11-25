package gen

// Param is one query parameter of an operation.
type Param struct {
	Name        string   `json:"name"`
	Type        string   `json:"type"`
	Required    bool     `json:"required,omitempty"`
	Description string   `json:"description,omitempty"`
	Enum        []string `json:"enum,omitempty"`
}

// Op is one CLI command derived from one OpenAPI operation.
type Op struct {
	Name         []string `json:"name"`
	Method       string   `json:"method"`
	Path         string   `json:"path"`
	ID           string   `json:"id"`
	Summary      string   `json:"summary,omitempty"`
	PathParams   []string `json:"pathParams,omitempty"`
	Query        []Param  `json:"query,omitempty"`
	HasBody      bool     `json:"hasBody,omitempty"`
	BodyRequired bool     `json:"bodyRequired,omitempty"`
	Columns      []string `json:"columns,omitempty"`
}
