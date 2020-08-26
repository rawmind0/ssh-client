package ssh

import (
	"strings"

	ghodssyaml "github.com/ghodss/yaml"
	"gopkg.in/yaml.v2"
)

const separator = ","

func newErrorByChan() (chan *string, []string) {
	wgErrors := make(chan *string)
	errStrings := []string{}

	return wgErrors, errStrings
}

func stringsToLines(input []string) string {
	return strings.Join(input, "\n")
}

func stringsToCmd(input []string) string {
	return strings.Join(input, " && ")
}

func stringsToInterface(in []string) []interface{} {
	out := make([]interface{}, len(in))
	for i, v := range in {
		out[i] = v
	}
	return out
}

// SplitBySep func
func SplitBySep(s string) []interface{} {
	if len(s) == 0 {
		return nil
	}

	return stringsToInterface(strings.Split(s, separator))
}

// YAMLToInterface func
func YAMLToInterface(in string, out interface{}) error {
	if out == nil {
		return nil
	}
	err := yaml.Unmarshal([]byte(in), out)
	if err != nil {
		return err
	}
	return err
}

// GhodssYAMLToMapInterface func
func GhodssYAMLToMapInterface(in string) (map[string]interface{}, error) {
	out := make(map[string]interface{})
	err := ghodssyaml.Unmarshal([]byte(in), &out)
	if err != nil {
		return nil, err
	}
	return out, err
}

// InterfaceToYAML func
func InterfaceToYAML(in interface{}) (string, error) {
	if in == nil {
		return "", nil
	}
	out, err := yaml.Marshal(in)
	if err != nil {
		return "", err
	}
	return string(out), err
}
