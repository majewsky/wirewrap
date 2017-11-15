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
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

type section string

const (
	noSection        section = ""
	interfaceSection         = "Interface"
	peerSection              = "Peer"
	wirewrapSection          = "Wirewrap"
)

var rxSectionHead = regexp.MustCompile(`^\[\s*(\w+)\s*\]$`)

//FromString parses the given configuration file contents.
//The file is valid if an empty list of errors is returned.
func FromString(text []byte) (cfg Config, errs []error) {
	report := func(lineNo int, err error) {
		if err != nil {
			errs = append(errs, fmt.Errorf("error in line %d: %s", lineNo, err.Error()))
		}
	}

	//non-zero default values
	cfg.Wirewrap.LeaderKey = "/wirewrap/leader"

	//initial state
	currentSection := noSection
	var requiredKey *Key

	//this function is called at the end of a section, and checks if all required fields in this section have been given
	endCurrentSection := func(lineNo int) {
		switch currentSection {
		case interfaceSection:
			if requiredKey == nil {
				report(lineNo, errors.New("expected PrivateKey, found end of [Interface] section"))
			} else {
				cfg.Interface.PrivateKey = *requiredKey
			}
		case peerSection:
			idx := len(cfg.Peers) - 1
			if requiredKey == nil {
				report(lineNo, errors.New("expected PublicKey, found end of [Peer] section"))
			} else {
				cfg.Peers[idx].PublicKey = *requiredKey
			}
			if len(cfg.Peers[idx].AllowedIPs) == 0 {
				report(lineNo, errors.New("expected AllowedIPs, found end of [Peer] section"))
			}
		}
		requiredKey = nil
		currentSection = noSection
	}

	maxLineNo := 0
LINE:
	for lineNo, line := range strings.Split(string(text), "\n") {
		maxLineNo = lineNo //maxLineNo will have the last line number after the loop

		//skip empty lines, comments
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		//parse section heading
		match := rxSectionHead.FindStringSubmatch(line)
		if match != nil {
			//check closing section
			endCurrentSection(lineNo)
			//start new section
			switch match[0] {
			case "Interface":
				currentSection = interfaceSection
				continue LINE
			case "Peer":
				currentSection = peerSection
				cfg.Peers = append(cfg.Peers, PeerSection{})
				continue LINE
			case "Wirewrap":
				currentSection = wirewrapSection
				continue LINE
			default:
				report(lineNo, fmt.Errorf("unknown section type: %s", match[0]))
				continue LINE
			}
		}

		if currentSection == noSection {
			report(lineNo, fmt.Errorf("missing section header before directive"))
		}

		//parse "key = value" line format
		fields := strings.SplitN(line, "=", 2)
		if len(fields) != 2 {
			report(lineNo, fmt.Errorf("missing value for field %s", line))
			continue
		}
		key := strings.TrimSpace(fields[0])
		value := strings.TrimSpace(fields[1])
		if value == "" {
			report(lineNo, fmt.Errorf("missing value for field %s", line))
			continue
		}

		//parse value according to field type
		peerIdx := len(cfg.Peers) - 1
		var err error
		switch string(currentSection) + "/" + key {
		case "Interface/PrivateKey", "Peer/PublicKey":
			requiredKey, err = KeyFromString(value)
			report(lineNo, err)

		case "Interface/ListenPort":
			i, err := strconv.ParseUint(value, 10, 16)
			report(lineNo, err)
			i16 := uint16(i)
			cfg.Interface.ListenPort = &i16

		case "Interface/FwMark":
			if value == "off" {
				cfg.Interface.FwMark = nil
			} else {
				i, err := strconv.ParseUint(value, 10, 32)
				report(lineNo, err)
				i32 := uint32(i)
				if i32 == 0 {
					cfg.Interface.FwMark = nil
				} else {
					cfg.Interface.FwMark = &i32
				}
			}

		case "Interface/Address":
			foreachCommaSeparated(value, func(text string) {
				addr, err := AddressFromString(text)
				report(lineNo, err)
				cfg.Interface.Addresses = append(cfg.Interface.Addresses, addr)
			})

		case "Interface/DNS":
			foreachCommaSeparated(value, func(text string) {
				ip, err := IPFromString(text)
				report(lineNo, err)
				cfg.Interface.DNSServers = append(cfg.Interface.DNSServers, ip)
			})

		case "Interface/MTU":
			i, err := strconv.ParseUint(value, 10, 0)
			report(lineNo, err)
			cfg.Interface.MTU = uint(i)

		case "Interface/PreUp":
			cfg.Interface.PreUp = value
		case "Interface/PreDown":
			cfg.Interface.PreDown = value
		case "Interface/PostUp":
			cfg.Interface.PostUp = value
		case "Interface/PostDown":
			cfg.Interface.PostDown = value

		case "Peer/WirewrapID":
			cfg.Peers[peerIdx].WirewrapID = value

		case "Peer/PresharedKey":
			cfg.Peers[peerIdx].PresharedKey, err = KeyFromString(value)
			report(lineNo, err)

		case "Peer/Endpoint":
			e, err := EndpointFromString(value)
			report(lineNo, err)
			cfg.Peers[peerIdx].Endpoint = &e

		case "Peer/AllowedIPs":
			foreachCommaSeparated(value, func(text string) {
				addr, err := AddressFromString(text)
				report(lineNo, err)
				cfg.Peers[peerIdx].AllowedIPs = append(cfg.Peers[peerIdx].AllowedIPs, addr)
			})

		case "Peer/PersistentKeepalive":
			i, err := strconv.ParseUint(value, 10, 16)
			report(lineNo, err)
			cfg.Peers[peerIdx].PersistentKeepalive = uint16(i)

		case "Wirewrap/ID":
			cfg.Wirewrap.ID = value
		case "Wirewrap/LeaderKey":
			cfg.Wirewrap.LeaderKey = value

		case "Wirewrap/Etcd":
			foreachCommaSeparated(value, func(text string) {
				e, err := EndpointFromString(text)
				report(lineNo, err)
				cfg.Wirewrap.EtcdEndpoints = append(cfg.Wirewrap.EtcdEndpoints, e)
			})

		}
	}
	endCurrentSection(maxLineNo + 1)

	return
}

func foreachCommaSeparated(input string, callback func(string)) {
	fields := strings.Split(input, ",")
	for _, field := range fields {
		callback(strings.TrimSpace(field))
	}
}
