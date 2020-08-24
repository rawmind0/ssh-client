package ssh

import (
	"strings"

	ghodssyaml "github.com/ghodss/yaml"
	"gopkg.in/yaml.v2"
)

const separator = ","

func SplitBySep(s string) []interface{} {
	if len(s) == 0 {
		return nil
	}

	return toArrayInterface(strings.Split(s, separator))
}

func toArrayInterface(in []string) []interface{} {
	out := make([]interface{}, len(in))
	for i, v := range in {
		out[i] = v
	}
	return out
}

func YAMLToMapInterface(in string) (map[string]interface{}, error) {
	out := make(map[string]interface{})
	err := yaml.Unmarshal([]byte(in), &out)
	if err != nil {
		return nil, err
	}
	return out, err
}

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

func GhodssYAMLToMapInterface(in string) (map[string]interface{}, error) {
	out := make(map[string]interface{})
	err := ghodssyaml.Unmarshal([]byte(in), &out)
	if err != nil {
		return nil, err
	}
	return out, err
}

func GhodssYAMLToInterface(in string, out interface{}) error {
	if out == nil {
		return nil
	}
	err := ghodssyaml.Unmarshal([]byte(in), out)
	if err != nil {
		return err
	}
	return err
}

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

func InterfaceToGhodssYAML(in interface{}) (string, error) {
	if in == nil {
		return "", nil
	}
	out, err := ghodssyaml.Marshal(in)
	if err != nil {
		return "", err
	}
	return string(out), err
}
