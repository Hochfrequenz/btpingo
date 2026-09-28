module github.com/go-template-repository

go 1.21

require (
	github.com/corbym/gocrest v1.3.0
	github.com/stretchr/testify v1.12.1
)

require go.yaml.in/yaml/v3 v3.0.5 // indirect

replace github.com/hochfrequenz/go-template-repository/foo => ./foo
