/*******************************************************************************
*
* Copyright 2017 Stefan Majewsky <majewsky@gmx.net>
*
* This program is free software: you can redistribute it and/or modify it under
* the terms of the GNU General Public License as published by the Free Software
* Foundation, either version 3 of the License, or (at your option) any later
* version.
*
* This program is distributed in the hope that it will be useful, but WITHOUT ANY
* WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
* A PARTICULAR PURPOSE. See the GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License along with
* this program. If not, see <http://www.gnu.org/licenses/>.
*
*******************************************************************************/

package util

import (
	"log"
	"os"
	"strings"
)

var isDebug = os.Getenv("WIREWRAP_DEBUG") == "1"

func init() {
	log.SetOutput(os.Stdout)
}

//LogFatal logs a fatal error and terminates the program.
func LogFatal(msg string, args ...interface{}) {
	doLog("FATAL: "+msg, args)
	os.Exit(1)
}

//LogError logs a non-fatal error.
func LogError(msg string, args ...interface{}) {
	doLog("ERROR: "+msg, args)
}

//LogInfo logs an informational message.
func LogInfo(msg string, args ...interface{}) {
	doLog("INFO: "+msg, args)
}

//LogDebug logs a debug message if debug logging is enabled.
func LogDebug(msg string, args ...interface{}) {
	if isDebug {
		doLog("DEBUG: "+msg, args)
	}
}

func doLog(msg string, args []interface{}) {
	msg = strings.TrimPrefix(msg, "\n")
	msg = strings.Replace(msg, "\n", "\\n", -1) //avoid multiline log messages
	if len(args) > 0 {
		log.Printf(msg+"\n", args...)
	} else {
		log.Println(msg)
	}
}
