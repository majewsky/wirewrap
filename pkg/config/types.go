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

import (
	"encoding/base64"
	"fmt"
	"net"
	"strconv"
	"strings"
)

//Address is an IP address, optionally within a network.
type Address struct {
	IP    net.IP
	IPNet *net.IPNet
}

//AddressFromString parses the string representation of an address (in CIDR
//notation, or as a plain IP) as it appears in the config file.
func AddressFromString(text string) (Address, error) {
	if strings.Contains(text, "/") {
		ip, net, err := net.ParseCIDR(text)
		return Address{ip, net}, err
	}
	ip, err := IPFromString(text)
	return Address{ip, nil}, err
}

//IPFromString is like net.ParseIP(), but returns an error instead of only nil on failure.
func IPFromString(text string) (net.IP, error) {
	ip := net.ParseIP(text)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP address: %s", text)
	}
	return ip, nil
}

////////////////////////////////////////////////////////////////////////////////

//Endpoint is a pair of IP address or hostname and port.
type Endpoint struct {
	Host string
	Port uint16
}

//EndpointFromString parses the string representation (of the form "host:port")
//of an endpoint as it appears in the config file.
func EndpointFromString(text string) (Endpoint, error) {
	host, portStr, err := net.SplitHostPort(text)
	if err != nil {
		return Endpoint{}, err
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return Endpoint{}, err
	}

	return Endpoint{host, uint16(port)}, nil
}

//String returns the "host:port" representation of this endpoint.
func (e Endpoint) String() string {
	return fmt.Sprintf("%s:%d", e.Host, e.Port)
}

////////////////////////////////////////////////////////////////////////////////

//Key represents a private, public or preshared key.
type Key [32]byte

//KeyFromString parses the base64 representation of the key, as it appears in
//the config file.
func KeyFromString(text string) (*Key, error) {
	buf, err := base64.StdEncoding.DecodeString(text)
	if err != nil {
		return nil, err
	}
	if len(buf) != 32 {
		return nil, fmt.Errorf("expected key length of 256 bits, got %d bits", 8*len(buf))
	}

	var k Key
	copy(k[:], buf)
	return &k, nil
}

//String returns the base64 representation of this key.
func (k Key) String() string {
	return base64.StdEncoding.EncodeToString(k[:])
}
