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
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

//CollectStdout runs a command with the given text presented on stdin, and
//the resulting text printed on stdout. Error output is shown on os.Stderr.
func CollectStdout(cmd *exec.Cmd, stdin string) (string, error) {
	cmd.Stdin = bytes.NewReader([]byte(stdin))
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err != nil {
		err = fmt.Errorf("exec `%s` failed: %s", strings.Join(cmd.Args, " "), err.Error())
	}
	return buf.String(), err
}
