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

func fromLines(lines ...string) (Config, []error) {
	return FromString([]byte(strings.Join(lines, "\n")))
}

func makeExampleKeyDecoded(i int) (buf [32]byte) {
	b := byte('0') + byte(i)
	for i := range buf {
		buf[i] = b
	}
	return
}

func makeExampleKey(i int) string {
	buf := makeExampleKeyDecoded(i)
	return base64.StdEncoding.EncodeToString(buf[:])
}

func makeAddress(t *testing.T, cidr string) Address {
	ip, net, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Error(err.Error())
		t.FailNow()
	}
	return Address{ip, net}
}

func TestReadOverall(t *testing.T) {
	cfg, errs := fromLines(
		"[Interface]",
		"PrivateKey = "+makeExampleKey(1),
		"[Peer]",
		"PublicKey = "+makeExampleKey(2),
		"AllowedIPs = 1.2.3.4/32",
	)
	if len(errs) > 0 {
		t.Error("expected parsing success, found errors:")
		for _, err := range errs {
			t.Log(err.Error())
		}
	}
	expected := Config{
		Interface: InterfaceSection{
			PrivateKey: makeExampleKeyDecoded(1),
		},
		Peers: []PeerSection{{
			PublicKey:  makeExampleKeyDecoded(2),
			AllowedIPs: []Address{makeAddress(t, "1.2.3.4/32")},
		}},
		Wirewrap: WirewrapSection{
			LeaderKey: "/wirewrap/leader",
		},
	}
	if !reflect.DeepEqual(cfg, expected) {
		t.Errorf("expected config = %#v\n", expected)
		t.Errorf("     got config = %#v\n", cfg)
	}
}
