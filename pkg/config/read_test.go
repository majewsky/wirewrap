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
	"net"
	"reflect"
	"strings"
	"testing"
)

var minimalInterfaceStr = "[Interface]\nPrivateKey = " + makeKey(1)
var minimalPeerStr = "[Peer]\nPublicKey = " + makeKey(2) + "\nAllowedIPs = 1.2.3.4/32"
var minimalWirewrapStr = ""

var minimalInterfaceSection = InterfaceSection{
	PrivateKey: makeKeyDecoded(1),
}
var minimalPeerSection = PeerSection{
	PublicKey:  makeKeyDecoded(2),
	AllowedIPs: []Address{makeAddressFromCIDR("1.2.3.4/32")},
}
var minimalWirewrapSection = WirewrapSection{
	LeaderKey: "/wirewrap/leader",
}

func TestReadMinimal(t *testing.T) {
	expectParseSuccess(t, join(
		minimalInterfaceStr,
		minimalPeerStr,
		minimalWirewrapStr,
	), Config{
		Interface: minimalInterfaceSection,
		Peers:     []PeerSection{minimalPeerSection},
		Wirewrap:  minimalWirewrapSection,
	})
}

func TestReadInterfacePrivateKey(t *testing.T) {
	expectParseError(t, join(
		"[Interface]",
		minimalPeerStr,
		minimalWirewrapStr,
	), "error in line 2: expected PrivateKey, found end of [Interface] section")

	expectParseError(t, join(
		"[Interface]",
		"PrivateKey = test",
		minimalPeerStr,
		minimalWirewrapStr,
	), "error in line 2: expected key length of 256 bits, got 24 bits")
}

func TestReadInterfaceListenPort(t *testing.T) {
	expectParseSuccess(t, join(
		minimalInterfaceStr,
		"ListenPort = 1234",
		minimalPeerStr,
		minimalWirewrapStr,
	), Config{
		Interface: InterfaceSection{
			PrivateKey: makeKeyDecoded(1),
			ListenPort: pointerToUint16(1234),
		},
		Peers:    []PeerSection{minimalPeerSection},
		Wirewrap: minimalWirewrapSection,
	})

	expectParseError(t, join(
		minimalInterfaceStr,
		"ListenPort = off",
		minimalPeerStr,
		minimalWirewrapStr,
	), "error in line 3: strconv.ParseUint: parsing \"off\": invalid syntax")

	expectParseError(t, join(
		minimalInterfaceStr,
		"ListenPort = 65536",
		minimalPeerStr,
		minimalWirewrapStr,
	), "error in line 3: strconv.ParseUint: parsing \"65536\": value out of range")
}

func TestReadInterfaceFwMark(t *testing.T) {
	expectParseSuccess(t, join(
		minimalInterfaceStr,
		"FwMark = 65536",
		minimalPeerStr,
		minimalWirewrapStr,
	), Config{
		Interface: InterfaceSection{
			PrivateKey: makeKeyDecoded(1),
			FwMark:     pointerToUint32(65536),
		},
		Peers:    []PeerSection{minimalPeerSection},
		Wirewrap: minimalWirewrapSection,
	})

	expectParseSuccess(t, join(
		minimalInterfaceStr,
		"FwMark = off",
		minimalPeerStr,
		minimalWirewrapStr,
	), Config{
		Interface: minimalInterfaceSection,
		Peers:     []PeerSection{minimalPeerSection},
		Wirewrap:  minimalWirewrapSection,
	})

	expectParseError(t, join(
		minimalInterfaceStr,
		"FwMark = 4294967296",
		minimalPeerStr,
		minimalWirewrapStr,
	), "error in line 3: strconv.ParseUint: parsing \"4294967296\": value out of range")
}

func TestReadAddresses(t *testing.T) {
	expectParseSuccess(t, join(
		minimalInterfaceStr,
		"Address = 192.168.0.1/24",
		"Address = 10.1.2.3",
		"Address = 1234::1/64",
		"Address = 1234::2",
		minimalPeerStr,
		minimalWirewrapStr,
	), Config{
		Interface: InterfaceSection{
			PrivateKey: makeKeyDecoded(1),
			Addresses: []Address{
				makeAddressFromCIDR("192.168.0.1/24"),
				makeAddressFromIP("10.1.2.3"),
				makeAddressFromCIDR("1234::1/64"),
				makeAddressFromIP("1234::2"),
			},
		},
		Peers:    []PeerSection{minimalPeerSection},
		Wirewrap: minimalWirewrapSection,
	})

	expectParseError(t, join(
		minimalInterfaceStr,
		"Address = 256.0.0.1/24",
		"Address = dead:beef:what::1",
		minimalPeerStr,
		minimalWirewrapStr,
	),
		"error in line 3: invalid CIDR address: 256.0.0.1/24",
		"error in line 4: invalid IP address: dead:beef:what::1",
	)
}

////////////////////////////////////////////////////////////////////////////////

func expectParseSuccess(t *testing.T, input []byte, expected Config) {
	t.Helper()
	cfg, errs := FromString(input)
	if len(errs) > 0 {
		t.Error("expected parsing success, found errors:")
		for _, err := range errs {
			t.Log(err.Error())
		}
	} else if !reflect.DeepEqual(cfg, expected) {
		t.Errorf("expected config = %#v\n", expected)
		t.Errorf("     got config = %#v\n", cfg)
	}
}

func expectParseError(t *testing.T, input []byte, expected ...string) {
	t.Helper()
	_, errs := FromString(input)

	if len(errs) != len(expected) {
		t.Errorf("expected %d parse errors:\n", len(expected))
		for _, msg := range expected {
			t.Log(msg)
		}
		if len(errs) == 0 {
			t.Error("got 0 parse errors")
		} else {
			t.Errorf("got %d parse errors:\n", len(errs))
			for _, err := range errs {
				t.Log(err.Error())
			}
		}
		return
	}

	for idx, err := range errs {
		if err.Error() != expected[idx] {
			t.Errorf("parse error %d of %d expected errors does not match expectation\n",
				idx+1, len(expected),
			)
			t.Errorf("expected: %s\n     got: %s\n", expected[idx], err.Error())
		}
	}
}

func join(lines ...string) []byte {
	return []byte(strings.Join(lines, "\n"))
}

func makeKeyDecoded(i int) (buf [32]byte) {
	b := byte('0') + byte(i)
	for i := range buf {
		buf[i] = b
	}
	return
}

func makeKey(i int) string {
	buf := makeKeyDecoded(i)
	return base64.StdEncoding.EncodeToString(buf[:])
}

func makeAddressFromCIDR(cidr string) Address {
	ip, net, err := net.ParseCIDR(cidr)
	if err != nil {
		panic(err.Error())
	}
	return Address{ip, net}
}

func makeAddressFromIP(ipStr string) Address {
	ip := net.ParseIP(ipStr)
	if len(ip) == 0 {
		panic(ipStr + " is not a valid IP")
	}
	return Address{ip, nil}
}

func pointerToUint16(val uint16) *uint16 {
	return &val
}

func pointerToUint32(val uint32) *uint32 {
	return &val
}
