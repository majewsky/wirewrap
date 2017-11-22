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

var minimalInterfaceStr = "[ Interface\t]\nPrivateKey = " + makeKey(1)
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

func TestReadGeneralSyntaxErrors(t *testing.T) {
	expectParseError(t, join(
		"Key = outside section",
		minimalInterfaceStr,
		minimalPeerStr,
		minimalWirewrapStr,
	), "error in line 1: missing section header before directive")

	expectParseError(t, join(
		minimalInterfaceStr,
		minimalPeerStr,
		"AllowedIPs",
		minimalWirewrapStr,
	), "error in line 6: missing value for field AllowedIPs")

	expectParseError(t, join(
		minimalInterfaceStr,
		minimalPeerStr,
		"AllowedIPs =   \t",
		minimalWirewrapStr,
	), "error in line 6: missing value for field AllowedIPs")

	expectParseError(t, join(
		minimalInterfaceStr,
		minimalPeerStr,
		"[Weird Section]",
		minimalWirewrapStr,
	), "error in line 6: unknown section type: [Weird Section]")

	expectParseError(t, join(
		minimalInterfaceStr,
		minimalPeerStr,
		"WeirdKey = value",
		minimalWirewrapStr,
	), "error in line 6: unknown directive in Peer section: WeirdKey")
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

	expectParseError(t, join(
		"[Interface]",
		"PrivateKey = a+#f%/",
		minimalPeerStr,
		minimalWirewrapStr,
	), "error in line 2: illegal base64 data at input byte 2")
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
			FwMark:     65536,
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

func TestReadInterfaceAddresses(t *testing.T) {
	expectParseSuccess(t, join(
		minimalInterfaceStr,
		"Address = 192.168.0.1/24",
		"Address = 10.1.2.3, 1234::1/64",
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

func TestReadInterfaceDNS(t *testing.T) {
	expectParseSuccess(t, join(
		minimalInterfaceStr,
		"DNS = 192.168.0.1",
		"DNS = 1234::1",
		minimalPeerStr,
		minimalWirewrapStr,
	), Config{
		Interface: InterfaceSection{
			PrivateKey: makeKeyDecoded(1),
			DNSServers: []net.IP{
				makeIP("192.168.0.1"),
				makeIP("1234::1"),
			},
		},
		Peers:    []PeerSection{minimalPeerSection},
		Wirewrap: minimalWirewrapSection,
	})

	expectParseError(t, join(
		minimalInterfaceStr,
		"DNS = 192.168.0.1/32",
		"DNS = something else",
		minimalPeerStr,
		minimalWirewrapStr,
	),
		"error in line 3: invalid IP address: 192.168.0.1/32",
		"error in line 4: invalid IP address: something else",
	)
}

func TestReadInterfaceMTU(t *testing.T) {
	expectParseSuccess(t, join(
		minimalInterfaceStr,
		"MTU = 9450",
		minimalPeerStr,
		minimalWirewrapStr,
	), Config{
		Interface: InterfaceSection{
			PrivateKey: makeKeyDecoded(1),
			MTU:        9450,
		},
		Peers:    []PeerSection{minimalPeerSection},
		Wirewrap: minimalWirewrapSection,
	})

	expectParseError(t, join(
		minimalInterfaceStr,
		"MTU = -9450",
		minimalPeerStr,
		minimalWirewrapStr,
	), "error in line 3: strconv.ParseUint: parsing \"-9450\": invalid syntax")
}

func TestReadInterfacePreAndPostUpAndDown(t *testing.T) {
	//there is no error case here; every value is valid
	expectParseSuccess(t, join(
		minimalInterfaceStr,
		"PreUp = foo 123",
		"PostUp = bar 234",
		"PreDown = baz 345",
		"PostDown = qux 456",
		minimalPeerStr,
		minimalWirewrapStr,
	), Config{
		Interface: InterfaceSection{
			PrivateKey: makeKeyDecoded(1),
			PreUp:      "foo 123",
			PostUp:     "bar 234",
			PreDown:    "baz 345",
			PostDown:   "qux 456",
		},
		Peers:    []PeerSection{minimalPeerSection},
		Wirewrap: minimalWirewrapSection,
	})
}

func TestReadPeerWirewrapID(t *testing.T) {
	//there is no error case here; every value is valid
	expectParseSuccess(t, join(
		minimalInterfaceStr,
		minimalPeerStr,
		"WirewrapID = foo bar\t",
		minimalWirewrapStr,
	), Config{
		Interface: minimalInterfaceSection,
		Peers: []PeerSection{{
			WirewrapID: "foo bar",
			PublicKey:  makeKeyDecoded(2),
			AllowedIPs: []Address{makeAddressFromCIDR("1.2.3.4/32")},
		}},
		Wirewrap: minimalWirewrapSection,
	})
}

func TestReadPeerPublicKey(t *testing.T) {
	expectParseError(t, join(
		minimalInterfaceStr,
		"[Peer]",
		"AllowedIPs = 1.2.3.4/32",
		minimalWirewrapStr,
	), "error in line 6: expected PublicKey, found end of [Peer] section")

	expectParseError(t, join(
		minimalInterfaceStr,
		"[Peer]",
		"PublicKey = test",
		"AllowedIPs = 1.2.3.4/32",
		minimalWirewrapStr,
	), "error in line 4: expected key length of 256 bits, got 24 bits")

	expectParseError(t, join(
		minimalInterfaceStr,
		"[Peer]",
		"PublicKey = a+#f%/",
		"AllowedIPs = 1.2.3.4/32",
		minimalWirewrapStr,
	), "error in line 4: illegal base64 data at input byte 2")
}

func TestReadPeerPresharedKey(t *testing.T) {
	expectParseSuccess(t, join(
		minimalInterfaceStr,
		minimalPeerStr,
		"PresharedKey = "+makeKey(3),
		minimalWirewrapStr,
	), Config{
		Interface: minimalInterfaceSection,
		Peers: []PeerSection{{
			PublicKey:    makeKeyDecoded(2),
			PresharedKey: pointerToKey(makeKeyDecoded(3)),
			AllowedIPs:   []Address{makeAddressFromCIDR("1.2.3.4/32")},
		}},
		Wirewrap: minimalWirewrapSection,
	})

	expectParseError(t, join(
		minimalInterfaceStr,
		minimalPeerStr,
		"PresharedKey = test",
		minimalWirewrapStr,
	), "error in line 6: expected key length of 256 bits, got 24 bits")

	expectParseError(t, join(
		minimalInterfaceStr,
		minimalPeerStr,
		"PresharedKey = a+#f%/",
		minimalWirewrapStr,
	), "error in line 6: illegal base64 data at input byte 2")
}

func TestReadPeerEndpoint(t *testing.T) {
	expectParseSuccess(t, join(
		minimalInterfaceStr,
		minimalPeerStr,
		"Endpoint = 11.22.33.44:5678",
		minimalWirewrapStr,
	), Config{
		Interface: minimalInterfaceSection,
		Peers: []PeerSection{{
			PublicKey:  makeKeyDecoded(2),
			Endpoint:   makeEndpoint("11.22.33.44", 5678),
			AllowedIPs: []Address{makeAddressFromCIDR("1.2.3.4/32")},
		}},
		Wirewrap: minimalWirewrapSection,
	})

	expectParseSuccess(t, join(
		minimalInterfaceStr,
		minimalPeerStr,
		"Endpoint = test.example.org:5678",
		minimalWirewrapStr,
	), Config{
		Interface: minimalInterfaceSection,
		Peers: []PeerSection{{
			PublicKey:  makeKeyDecoded(2),
			Endpoint:   makeEndpoint("test.example.org", 5678),
			AllowedIPs: []Address{makeAddressFromCIDR("1.2.3.4/32")},
		}},
		Wirewrap: minimalWirewrapSection,
	})

	expectParseError(t, join(
		minimalInterfaceStr,
		minimalPeerStr,
		"Endpoint = incomplete.example.org",
		minimalWirewrapStr,
	), "error in line 6: address incomplete.example.org: missing port in address")

	expectParseError(t, join(
		minimalInterfaceStr,
		minimalPeerStr,
		"Endpoint = incorrect.example:org",
		minimalWirewrapStr,
	), "error in line 6: strconv.ParseUint: parsing \"org\": invalid syntax")
}

func TestReadPeerAllowedIPs(t *testing.T) {
	expectParseSuccess(t, join(
		minimalInterfaceStr,
		"[Peer]",
		"PublicKey = "+makeKey(2),
		"AllowedIPs = 192.168.0.1/24",
		"AllowedIPs = 10.1.2.3, 1234::1/64",
		"AllowedIPs = 1234::2",
		minimalWirewrapStr,
	), Config{
		Interface: minimalInterfaceSection,
		Peers: []PeerSection{{
			PublicKey: makeKeyDecoded(2),
			AllowedIPs: []Address{
				makeAddressFromCIDR("192.168.0.1/24"),
				makeAddressFromIP("10.1.2.3"),
				makeAddressFromCIDR("1234::1/64"),
				makeAddressFromIP("1234::2"),
			},
		}},
		Wirewrap: minimalWirewrapSection,
	})

	expectParseError(t, join(
		minimalInterfaceStr,
		"[Peer]",
		"PublicKey = "+makeKey(2),
		"AllowedIPs = 256.0.0.1/24",
		"AllowedIPs = dead:beef:what::1",
		minimalWirewrapStr,
	),
		"error in line 5: invalid CIDR address: 256.0.0.1/24",
		"error in line 6: invalid IP address: dead:beef:what::1",
	)

	expectParseError(t, join(
		minimalInterfaceStr,
		"[Peer]",
		"PublicKey = "+makeKey(2),
		minimalWirewrapStr,
	), "error in line 6: expected AllowedIPs, found end of [Peer] section")
}

func TestReadPeerPersistentKeepalive(t *testing.T) {
	expectParseSuccess(t, join(
		minimalInterfaceStr,
		minimalPeerStr,
		"PersistentKeepalive = 10",
		minimalWirewrapStr,
	), Config{
		Interface: minimalInterfaceSection,
		Peers: []PeerSection{{
			PublicKey:           makeKeyDecoded(2),
			AllowedIPs:          []Address{makeAddressFromCIDR("1.2.3.4/32")},
			PersistentKeepalive: 10,
		}},
		Wirewrap: minimalWirewrapSection,
	})

	expectParseSuccess(t, join(
		minimalInterfaceStr,
		minimalPeerStr,
		"PersistentKeepalive = off",
		minimalWirewrapStr,
	), Config{
		Interface: minimalInterfaceSection,
		Peers:     []PeerSection{minimalPeerSection},
		Wirewrap:  minimalWirewrapSection,
	})

	expectParseError(t, join(
		minimalInterfaceStr,
		minimalPeerStr,
		"PersistentKeepalive = 65536",
		minimalWirewrapStr,
	), "error in line 6: strconv.ParseUint: parsing \"65536\": value out of range")
}

func TestReadWirewrapIDAndEtcdEndpoints(t *testing.T) {
	expectParseSuccess(t, join(
		minimalInterfaceStr,
		minimalPeerStr,
		"[Wirewrap]",
		"ID = foo bar",
		"Etcd = 11.22.33.44:5678, [1234::1]:567",
	), Config{
		Interface: minimalInterfaceSection,
		Peers:     []PeerSection{minimalPeerSection},
		Wirewrap: WirewrapSection{
			ID:        "foo bar",
			LeaderKey: "/wirewrap/leader",
			EtcdEndpoints: []Endpoint{
				Endpoint{Host: "11.22.33.44", Port: 5678},
				Endpoint{Host: "1234::1", Port: 567},
			},
		},
	})

	expectParseError(t, join(
		minimalInterfaceStr,
		minimalPeerStr,
		"[Wirewrap]",
	),
		"error in line 7: expected ID, found end of [Wirewrap] section",
		"error in line 7: expected EtcdEndpoints, found end of [Wirewrap] section",
	)

	expectParseError(t, join(
		minimalInterfaceStr,
		minimalPeerStr,
		"[Wirewrap]",
		"ID = foo bar",
		"Etcd = incomplete.example.org",
		"Etcd = incorrect.example:org",
	),
		"error in line 8: address incomplete.example.org: missing port in address",
		"error in line 9: strconv.ParseUint: parsing \"org\": invalid syntax",
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
			t.Errorf("parse error %d/%d does not match expectation\n",
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
	return Address{makeIP(ipStr), nil}
}

func makeEndpoint(host string, port uint16) *Endpoint {
	return &Endpoint{host, port}
}

func makeIP(ipStr string) net.IP {
	ip := net.ParseIP(ipStr)
	if len(ip) == 0 {
		panic(ipStr + " is not a valid IP")
	}
	return ip
}

func pointerToUint16(val uint16) *uint16 {
	return &val
}

func pointerToUint32(val uint32) *uint32 {
	return &val
}

func pointerToKey(val Key) *Key {
	return &val
}
