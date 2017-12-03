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

var minimalInterfaceStr = "[ Interface\t]\nPrivateKey = " + encodeKey(testKeysPrivate[0])
var minimalPeerStr = "[Peer]\nPublicKey = " + encodeKey(testKeysPublic[1]) + "\nAllowedIPs = 1.2.3.4/32"
var minimalWirewrapStr = ""

var minimalInterfaceSection = InterfaceSection{
	KeyPair: KeyPair{testKeysPrivate[0], testKeysPublic[0]},
}
var minimalPeerSection = PeerSection{
	PublicKey:  testKeysPublic[1],
	AllowedIPs: []Address{makeAddressFromCIDR("1.2.3.4/32")},
}
var minimalWirewrapSection = WirewrapSection{}

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
			KeyPair:    KeyPair{testKeysPrivate[0], testKeysPublic[0]},
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
			KeyPair: KeyPair{testKeysPrivate[0], testKeysPublic[0]},
			FwMark:  65536,
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
			KeyPair: KeyPair{testKeysPrivate[0], testKeysPublic[0]},
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
			KeyPair: KeyPair{testKeysPrivate[0], testKeysPublic[0]},
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
			KeyPair: KeyPair{testKeysPrivate[0], testKeysPublic[0]},
			MTU:     9450,
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
			KeyPair:  KeyPair{testKeysPrivate[0], testKeysPublic[0]},
			PreUp:    "foo 123",
			PostUp:   "bar 234",
			PreDown:  "baz 345",
			PostDown: "qux 456",
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
			PublicKey:  testKeysPublic[1],
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
		"PresharedKey = "+encodeKey(testKeysPublic[2]),
		minimalWirewrapStr,
	), Config{
		Interface: minimalInterfaceSection,
		Peers: []PeerSection{{
			PublicKey:    testKeysPublic[1],
			PresharedKey: pointerToKey(testKeysPublic[2]),
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
			PublicKey:  testKeysPublic[1],
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
			PublicKey:  testKeysPublic[1],
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
		"PublicKey = "+encodeKey(testKeysPublic[1]),
		"AllowedIPs = 192.168.0.1/24",
		"AllowedIPs = 10.1.2.3, 1234::1/64",
		"AllowedIPs = 1234::2",
		minimalWirewrapStr,
	), Config{
		Interface: minimalInterfaceSection,
		Peers: []PeerSection{{
			PublicKey: testKeysPublic[1],
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
		"PublicKey = "+encodeKey(testKeysPublic[1]),
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
		"PublicKey = "+encodeKey(testKeysPublic[1]),
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
			PublicKey:           testKeysPublic[1],
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
			ID: "foo bar",
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

//These test keys were generated with the following shell script:
//
//  key_to_bytearray() {
//    base64 -d | xxd -p -c 32 | sed 's/.\{2\}/0x&, /g;s/^/Key{/;s/, $/}/'
//  }
//  for i in {1..5}; do
//    KEY="$(wg genkey)"
//    echo -n "private: "
//    echo "$KEY" | key_to_bytearray
//    echo -n "public:  "
//    echo "$KEY" | wg pubkey | key_to_bytearray
//  done
var testKeysPrivate = []Key{
	Key{0x20, 0xeb, 0xe4, 0xe9, 0x66, 0x95, 0x4e, 0x61, 0xbb, 0xdd, 0x62, 0x87, 0x1f, 0xf8, 0xc7, 0x66, 0x7f, 0x1e, 0xf3, 0xc3, 0x5c, 0x8b, 0x92, 0x0e, 0x4f, 0x70, 0xa7, 0x63, 0xf3, 0x12, 0x62, 0x4b},
	Key{0xa8, 0xb1, 0xaf, 0xea, 0x1e, 0xba, 0x02, 0xba, 0x82, 0x17, 0x6a, 0x9c, 0xf0, 0x90, 0xc3, 0xf7, 0x1f, 0x03, 0xba, 0x76, 0x71, 0x11, 0xf4, 0xf1, 0x26, 0x8b, 0xbd, 0x9c, 0xc1, 0x7b, 0xd5, 0x46},
	Key{0xf8, 0xa5, 0x73, 0x1c, 0xd5, 0xf2, 0x9e, 0x48, 0xde, 0x86, 0x28, 0x1d, 0xc6, 0xc7, 0x4d, 0x69, 0x51, 0x04, 0x4a, 0x35, 0x72, 0x77, 0x57, 0xe3, 0xc8, 0x9c, 0xe0, 0x60, 0x47, 0x5d, 0xf0, 0x69},
	Key{0x08, 0xb9, 0x1e, 0x5d, 0x12, 0x20, 0x34, 0xf9, 0xe6, 0x3d, 0xc5, 0xc9, 0x79, 0x45, 0xbc, 0x86, 0xa8, 0x65, 0x66, 0xf1, 0x8b, 0xf6, 0xc3, 0xea, 0xff, 0xee, 0x03, 0xd9, 0xe6, 0x19, 0x2c, 0x78},
	Key{0xa0, 0xe0, 0x55, 0xef, 0xa1, 0x5f, 0x15, 0x17, 0xa5, 0x7f, 0xd8, 0xe7, 0xe7, 0xb2, 0x35, 0x74, 0x16, 0x40, 0xd7, 0x39, 0x20, 0x8b, 0x0f, 0x2f, 0x67, 0xb4, 0xca, 0x01, 0xd2, 0x63, 0x4b, 0x69},
}
var testKeysPublic = []Key{
	Key{0x77, 0x7e, 0x6d, 0x19, 0xce, 0x12, 0x13, 0x0e, 0x15, 0x9f, 0xfc, 0xe6, 0x2b, 0x27, 0x82, 0x64, 0x78, 0x06, 0x3a, 0xd4, 0xab, 0x55, 0xa5, 0x6b, 0x6f, 0x99, 0xc6, 0x37, 0x69, 0x2f, 0xb6, 0x62},
	Key{0xff, 0x54, 0x39, 0x03, 0xe2, 0x03, 0x0f, 0x7c, 0xef, 0x18, 0xf5, 0x13, 0xdd, 0xdd, 0x0d, 0x7e, 0x66, 0x4e, 0x25, 0x43, 0x69, 0x0e, 0x3e, 0xb0, 0x93, 0xc2, 0xa5, 0x5a, 0x94, 0x22, 0xd1, 0x26},
	Key{0xd6, 0x82, 0x9f, 0xcc, 0x64, 0xee, 0x6d, 0x3c, 0x87, 0xcf, 0x9b, 0x93, 0x27, 0xd4, 0x6e, 0x44, 0xea, 0x86, 0xce, 0x79, 0x60, 0xca, 0x1a, 0x27, 0xa4, 0x28, 0xb4, 0x0b, 0xcc, 0xee, 0x5d, 0x47},
	Key{0x9a, 0x4c, 0x57, 0x3b, 0x47, 0xc1, 0xa4, 0xe9, 0x51, 0xdd, 0x28, 0x66, 0xa7, 0xb1, 0xd0, 0xa2, 0xcc, 0x7e, 0x01, 0x4b, 0xf1, 0xf4, 0x54, 0x0a, 0x1f, 0xbe, 0x2e, 0x61, 0xaa, 0x63, 0x84, 0x43},
	Key{0x8e, 0xd3, 0x0e, 0x00, 0x12, 0x06, 0xdb, 0x07, 0x00, 0xa3, 0x47, 0xc1, 0x32, 0xbb, 0x17, 0xd1, 0xc1, 0x71, 0x46, 0x21, 0xbf, 0x88, 0xa5, 0xb6, 0x55, 0xe8, 0xb6, 0x47, 0xa6, 0x1c, 0x5c, 0x3a},
}

func encodeKey(testKey Key) string {
	return base64.StdEncoding.EncodeToString(testKey[:])
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
