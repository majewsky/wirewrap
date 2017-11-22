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

package config

import "testing"

func TestEndpointToString(t *testing.T) {
	//test that the following endpoints are not altered by parsing and successive
	//deparsing
	samples := []string{
		"example.org:1234",
		"11.22.33.44:5678",
		"[dead:beef::1]:1234",
	}
	for _, expected := range samples {
		e, err := EndpointFromString(expected)
		if err != nil {
			t.Errorf("unexpected error in EndpointFromString(%q): %s", expected, err.Error())
			continue
		}
		actual := e.String()
		if expected != actual {
			t.Errorf("Endpoint.String(): expected %q, got %q", expected, actual)
		}
	}
}

func TestKeyToString(t *testing.T) {
	//test that the following keys are not altered by parsing and successive
	//deparsing
	samples := []string{
		makeKey(1),
		makeKey(2),
		makeKey(3),
		makeKey(4),
		makeKey(5),
	}
	for _, expected := range samples {
		k, err := KeyFromString(expected)
		if err != nil {
			t.Errorf("unexpected error in KeyFromString(%q): %s", expected, err.Error())
			continue
		}
		actual := k.String()
		if expected != actual {
			t.Errorf("Key.String(): expected %q, got %q", expected, actual)
		}
	}
}
