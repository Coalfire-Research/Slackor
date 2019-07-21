# pkg
Implant commands live here. This package is subdivided by operating system,
using the same names as the golang `GOOS` environment variable, with the
exception of `common`, which contains commands that will run on all platforms.

Commands must satisfy the `Command` interface and must only take zero or more
`string` arguments. If an argument should be a number or other type, it will
need to be converted internally by the command.
