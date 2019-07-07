// Package command provides the common interface for all commands.
package command

// The Command interface provides a common interface for commands, simplifying
// the process of providing cross-platform and OS-specific commands.
type Command interface {
	// Name is the name of the command, what will appear in the help
	// documentation, and what the operator will type to run the command.
	Name() string
	// Run performs the command's operation.
	Run(args []string) (string, error)
}

var availableCommands = map[string]Command{}

// RegisterCommand registers a command for use by the implant.
//
// This is typically done immediately after declaring the command to make it
// easy to create the list of available commands at compile time for the
// target OS.
func RegisterCommand(cmd Command) {
	availableCommands[cmd.Name()] = cmd
}

// GetCommand returns the command with the given name or nil if it hasn't
// been registered or otherwise doesn't exist.
func GetCommand(name string) Command {
	return availableCommands[name]
}
