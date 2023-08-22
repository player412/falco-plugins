module github.com/falcosecurity/plugins/plugins/dummy

go 1.15

require (
	github.com/alecthomas/jsonschema v0.0.0-20220216202328-9eeeec9d044b
	github.com/falcosecurity/plugin-sdk-go v0.6.0
	github.com/valyala/fastjson v1.6.4 // indirect
	logfilevalidation.com/logfilevalidation v0.0.0
)
replace logfilevalidation.com/logfilevalidation => ./pkg/logfilevalidation
