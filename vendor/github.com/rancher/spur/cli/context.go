package cli

import (
	"context"
	"fmt"
	"reflect"
	"strings"

	"github.com/rancher/spur/flag"
)

// Context is a type that is passed through to
// each Handler action in a cli application. Context
// can be used to retrieve context-specific args and
// parsed command-line options.
type Context struct {
	context.Context
	App           *App
	Command       *Command
	shellComplete bool
	flagSet       *flag.FlagSet
	parentContext *Context
}

// NewContext creates a new context. For use in when invoking an App or Command action.
func NewContext(app *App, set *flag.FlagSet, parentCtx *Context) *Context {
	c := &Context{App: app, flagSet: set, parentContext: parentCtx}
	if parentCtx != nil {
		c.Context = parentCtx.Context
		c.shellComplete = parentCtx.shellComplete
		if parentCtx.flagSet == nil {
			parentCtx.flagSet = &flag.FlagSet{}
		}
	}

	c.Command = &Command{}

	if c.Context == nil {
		c.Context = context.Background()
	}

	return c
}

// NumFlags returns the number of flags set
func (c *Context) NumFlags() int {
	return c.flagSet.NFlag()
}

// Set sets a context flag to a value.
func (c *Context) Set(name string, value interface{}) error {
	return c.flagSet.Set(name, value)
}

// IsSet determines if the flag was actually set
func (c *Context) IsSet(name string) bool {
	if fs := lookupFlagSet(name, c); fs != nil {
		isSet := false
		fs.Visit(func(f *flag.Flag) {
			if f.Name == name {
				isSet = true
			}
		})
		if isSet {
			return true
		}
	}
	return false
}

// LocalFlagNames returns a slice of flag names used in this context.
func (c *Context) LocalFlagNames() []string {
	var names []string
	c.flagSet.Visit(makeFlagNameVisitor(&names))
	return names
}

// FlagNames returns a slice of flag names used by the this context and all of
// its parent contexts.
func (c *Context) FlagNames() []string {
	var names []string
	for _, ctx := range c.Lineage() {
		ctx.flagSet.Visit(makeFlagNameVisitor(&names))
	}
	return names
}

// Lineage returns *this* context and all of its ancestor contexts in order from
// child to parent
func (c *Context) Lineage() []*Context {
	var lineage []*Context

	for cur := c; cur != nil; cur = cur.parentContext {
		lineage = append(lineage, cur)
	}

	return lineage
}

// Value returns the value of the flag corresponding to `name`
func (c *Context) Value(name string) interface{} {
	return c.flagSet.Lookup(name).Value.(flag.Getter).Get()
}

// Args returns the command line arguments associated with the context.
func (c *Context) Args() Args {
	ret := args(c.flagSet.Args())
	return &ret
}

// NArg returns the number of the command line arguments.
func (c *Context) NArg() int {
	return c.Args().Len()
}

// Lookup will return the value for a flag, or the default value if
// the flag value does not exist or is not of the same type
func (c *Context) Lookup(name string, defaultVal interface{}) interface{} {
	var result interface{}
	if fs := lookupFlagSet(name, c); fs != nil {
		if f := fs.Lookup(name); f != nil {
			result = f.Value
		}
	}
	if result == nil {
		return defaultVal
	}
	// if we don't have a default value assume they want they flag.Value
	if defaultVal != nil {
		result = result.(flag.Getter).Get()
	}
	if defaultVal == nil || reflect.TypeOf(result) == reflect.TypeOf(defaultVal) {
		return result
	}
	return defaultVal
}

// GetFlags will return all of the flags found for this context
func (c *Context) GetFlags() []Flag {
	flags := []Flag{}
	for _, ctx := range c.Lineage() {
		if ctx.Command != nil {
			flags = append(flags, ctx.Command.Flags...)
		}
	}
	if c.App != nil {
		flags = append(flags, c.App.Flags...)
	}
	return flags
}

func lookupFlag(name string, ctx *Context) Flag {
	for _, f := range ctx.GetFlags() {
		for _, n := range FlagNames(f) {
			if n == name {
				return f
			}
		}
	}
	return nil
}

func lookupFlagSet(name string, ctx *Context) *flag.FlagSet {
	for _, c := range ctx.Lineage() {
		if f := c.flagSet.Lookup(name); f != nil {
			return c.flagSet
		}
	}

	return nil
}

func copyFlag(name string, ff *flag.Flag, set *flag.FlagSet) {
	set.Set(name, ff.Value.String())
}

func normalizeFlags(flags []Flag, set *flag.FlagSet) error {
	visited := make(map[string]bool)
	set.Visit(func(f *flag.Flag) {
		visited[f.Name] = true
	})
	for _, f := range flags {
		parts := FlagNames(f)
		if len(parts) == 1 {
			continue
		}
		var ff *flag.Flag
		for _, name := range parts {
			name = strings.Trim(name, " ")
			if visited[name] {
				ff = set.Lookup(name)
			}
		}
		if ff == nil {
			continue
		}
		for _, name := range parts {
			name = strings.Trim(name, " ")
			if !visited[name] {
				copyFlag(name, ff, set)
			}
		}
	}
	return nil
}

func makeFlagNameVisitor(names *[]string) func(*flag.Flag) {
	return func(f *flag.Flag) {
		nameParts := strings.Split(f.Name, ",")
		name := strings.TrimSpace(nameParts[0])

		for _, part := range nameParts {
			part = strings.TrimSpace(part)
			if len(part) > len(name) {
				name = part
			}
		}

		if name != "" {
			*names = append(*names, name)
		}
	}
}

type requiredFlagsErr interface {
	error
	getMissingFlags() []string
}

type errRequiredFlags struct {
	missingFlags []string
}

func (e *errRequiredFlags) Error() string {
	numberOfMissingFlags := len(e.missingFlags)
	if numberOfMissingFlags == 1 {
		return fmt.Sprintf("Required flag %q not set", e.missingFlags[0])
	}
	joinedMissingFlags := strings.Join(e.missingFlags, ", ")
	return fmt.Sprintf("Required flags %q not set", joinedMissingFlags)
}

func (e *errRequiredFlags) getMissingFlags() []string {
	return e.missingFlags
}

func checkRequiredFlags(flags []Flag, context *Context) requiredFlagsErr {
	var missingFlags []string
	for _, f := range flags {
		if required, ok := getFlagRequired(f); ok && required {
			var flagPresent bool
			var flagName string

			for _, key := range FlagNames(f) {
				if len(key) > 1 {
					flagName = key
				}

				if context.IsSet(strings.TrimSpace(key)) {
					flagPresent = true
				}
			}

			if !flagPresent && flagName != "" {
				missingFlags = append(missingFlags, flagName)
			}
		}
	}

	if len(missingFlags) != 0 {
		return &errRequiredFlags{missingFlags: missingFlags}
	}

	return nil
}
