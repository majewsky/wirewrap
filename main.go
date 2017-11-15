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

package main

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/majewsky/wirewrap/pkg/config"
)

func main() {
	err := run()
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) != 2 {
		return errors.New("usage: wirewrap <config-file>")
	}

	buf, err := ioutil.ReadFile(os.Args[0])
	if err != nil {
		return err
	}

	cfg, errs := config.FromString(buf)
	if len(errs) != 0 {
		return multiError(errs)
	}

	//TODO
	fmt.Printf("config = %#v\n", cfg)
	return nil
}

//multiError is an error containing multiple errors.
type multiError []error

func (e multiError) Error() string {
	s := make([]string, len(e))
	for idx, err := range e {
		s[idx] = err.Error()
	}
	return strings.Join(s, "\n")
}
