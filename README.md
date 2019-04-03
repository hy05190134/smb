#
# SMB
A Go package for communicating over SMB. Currently only minimal funcationality exists for client-side functions.

Here is a sample client that establishes a session with a server:

```go
package main

import (
	"github.com/hy05190134/smb/common"
	"github.com/hy05190134/smb/smb"
	"log"
)

func main() {
	common.SetLogger(common.NewConsoleLogger(common.LogLevelDebug))

	host := "127.0.0.1"
	options := smb.Options{
		Host:        host,
		Port:        445,
		User:        "sandy",
		Domain:      "",
		Workstation: "",
		Password:    "57002680",
	}
	debug := true
	session, err := smb.NewSession(options, debug)
	if err != nil {
		log.Fatalln("[!]", err)
	}
	defer session.Close()

	if session.IsSigningRequired {
		common.Log.Trace("Signing is required")
	} else {
		common.Log.Trace("Signing is NOT required")
	}

	if session.IsAuthenticated {
		common.Log.Trace("Login successful")
	} else {
		common.Log.Trace("Login failed")
	}

	err = session.TreeConnect("ts")
	if err != nil {
		common.Log.Debug("connect aab failed, err: %s", err)
		return
	}

	err = session.OpenFile("ts", "readme.txt")
	if err != nil {
		common.Log.Debug("open file readme.txt failed, err: %s", err)
		return
	}

	err = session.ReadFile("ts")
	if err != nil {
		common.Log.Debug("read file readme.txt failed, err: %s", err)
		return
	}

	err = session.CloseFile("ts")
	if err != nil {
		common.Log.Debug("close file readme.txt failed, err: %s", err)
		return
	}
}

```
