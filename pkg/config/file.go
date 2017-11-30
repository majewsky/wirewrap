/*******************************************************************************
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

package config

import (
	"io/ioutil"
	"strings"
)

//FromFile reads the given configuration file.
func FromFile(path string) (Config, error) {
	buf, err := ioutil.ReadFile(path)
	if err != nil {
		return Config{}, err
	}

	cfg, errs := FromString(buf)
	if len(errs) != 0 {
		return Config{}, multiError(errs)
	}

	return cfg, nil
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
