module github.com/falcosecurity/plugins/plugins/dummy

go 1.15

require (
	github.com/alecthomas/jsonschema v0.0.0-20220216202328-9eeeec9d044b
	github.com/falcosecurity/plugin-sdk-go v0.6.0
	github.com/valyala/fastjson v1.6.4 // indirect
	publicaccessblock.com/publicaccessblock v0.0.0
)
replace publicaccessblock.com/publicaccessblock => ./pkg/publicaccessblock