package iammfa

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os/exec"
	"time"
	"bytes"
	//"strconv"

	"github.com/alecthomas/jsonschema"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/source"
	"github.com/valyala/fastjson"
)

const (
	PluginID          uint32 = 17
	PluginName               = "iammfa"
	PluginDescription        = "Reference plugin for educational purposes"
	PluginContact            = "github.com/falcosecurity/plugins"
	PluginVersion            = "0.9.0"
	PluginEventSource        = "iammfa"
)

type PluginConfig struct {
	FilePath string `json:"file_path" jsonschema:"title=File Path,description=Path to the JSON log file"`
}

type Plugin struct {
	plugins.BasePlugin
	// Contains the init configuration values
	config PluginConfig
	jparser     fastjson.Parser
	jdata       *fastjson.Value
	jdataEvtnum uint64 // The event number jdata refers to. Used to know when we can skip the unmarshaling.

}

func (p *PluginConfig) setDefault() {
	p.FilePath = "/usr/share/falco/plugins"
}

func (m *Plugin) Info() *plugins.Info {
	return &plugins.Info{
		ID:          PluginID,
		Name:        PluginName,
		Description: PluginDescription,
		Contact:     PluginContact,
		Version:     PluginVersion,
		EventSource: PluginEventSource,
	}
}

func (p *Plugin) InitSchema() *sdk.SchemaInfo {
return nil
}

func (p *Plugin) OpenParams() ([]sdk.OpenParam, error) {
	reflector := jsonschema.Reflector{
		// all properties are optional by default
		RequiredFromJSONSchemaTags: true,
		// unrecognized properties don't cause a parsing failures
		AllowAdditionalProperties: true,
	}
	schema := reflector.Reflect(&PluginConfig{})

	schemaJSON, err := json.Marshal(schema)
	if err != nil {
		return nil, err
	}

	return []sdk.OpenParam{
		{
			Value: string(schemaJSON),
			Desc:  "Schema for configuring the plugin",
		},
	}, nil
}

func (p *Plugin) Init(cfg string) error {
	// The format of cfg is a json object with a single param
	// "file_path", e.g. {"file_path": "/path/to/log.json"}
	// Empty configs are allowed, in which case the default is used.
	// Since we don't provide a schema, the framework won't validate the config.
	p.config.setDefault()
	json.Unmarshal([]byte(cfg), &p.config)

	return nil
}

func (p *Plugin) Destroy() {
	// nothing to do here
}

func (p *Plugin) Open(prms string) (source.Instance, error) {
	// Open the JSON log file
	// file, err := os.Open(p.config.FilePath)
	// if err != nil {
	//	return nil, fmt.Errorf("failed to open log file: %s", err.Error())
	// }
	// defer file.Close()


	// Read the JSON log file contents
	data, err := exec.Command("python3", "/usr/share/falco/plugins/botoscript/iammfa.py").Output()
	//fmt.Printf("\nData: %s",data)
	if err != nil {
		return nil, fmt.Errorf("failed to read log file: %s", err.Error())
	}

	// Unmarshal the JSON log data into a slice of map[string]interface{}
	var logs []map[string]interface{}
	if err := json.Unmarshal(data, &logs); err != nil {
		return nil, fmt.Errorf("failed to parse log data: %s", err.Error())
	}

	// Create a new source instance
	pull := func(ctx context.Context, evt sdk.EventWriter) error {
		// Check if all logs have been read
		if len(logs) == 0 {
			return sdk.ErrEOF
		}

		// Get the first log from the slice
		log := logs[0]
		logs = logs[1:]

		// Marshal the log back to JSON
		logJSON, err := json.Marshal(log)
		if err != nil {
			return fmt.Errorf("failed to marshal log data: %s", err.Error())
		}


		// Set the log as the event data
		evt.SetTimestamp(uint64(time.Now().UnixNano()))
		_, err = evt.Writer().Write(logJSON)
		return err
	}

	return source.NewPullInstance(pull)
}

func (m *Plugin) Fields() []sdk.FieldEntry {
	return []sdk.FieldEntry{
		{Type: "string", Name: "iammfa.MFA", Display: "bucket", Desc: "Bucket name"},
		{Type: "string", Name: "iammfa.EventName", Display: "event", Desc: "Event Name"},

	}
}


func getfieldStr(jdata *fastjson.Value, field string) (bool, string) {
	var res string
	//var a string

	switch field {

	case "iammfa.EventName":
                val:=jdata.GetStringBytes("EventName")
                if val == nil {
                         return false, ""
                } else {
                        res = string(val)
                }
	case "iammfa.MFA":
		val:=jdata.GetStringBytes("MFA")
		if val == nil {
			 return false, ""
                } else {
                        res = string(val)
                }


	default:
		return false, ""
	}

	return true, res
}


func (p *Plugin) Extract(req sdk.ExtractRequest, evt sdk.EventReader) error {
// Decode the json, but only if we haven't done it yet for this event
	if evt.EventNum() != p.jdataEvtnum {
		// Read the event data
		data, err := ioutil.ReadAll(evt.Reader())
		if err != nil {
			return err
		}

		// Maybe temp--remove trailing null bytes from string
		data = bytes.Trim(data, "\x00")

		// For this plugin, events are always strings
		evtStr := string(data)

		p.jdata, err = p.jparser.Parse(evtStr)
		if err != nil {
			// Not a json file, so not present.
			return err
		}
		p.jdataEvtnum = evt.EventNum()

	}

	// Extract the field value
	present, value := getfieldStr(p.jdata, req.Field())
	if present {
		req.SetValue(value)
	}
    return nil
	}
