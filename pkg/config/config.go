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

import "net"

//Config holds the data from the config file.
type Config struct {
	Interface InterfaceSection
	Peers     []PeerSection
	Wirewrap  WirewrapSection
}

//InterfaceSection holds the data from the [Interface] section of the config file.
type InterfaceSection struct {
	PrivateKey Key
	ListenPort *uint16 //nil = choose randomly
	FwMark     uint32  //0 = off
	Addresses  []Address
	DNSServers []net.IP
	MTU        uint
	PreUp      string
	PreDown    string
	PostUp     string
	PostDown   string
}

//PeerSection holds the data from the [Peer] section of the config file.
type PeerSection struct {
	WirewrapID          string
	PublicKey           Key
	PresharedKey        *Key
	Endpoint            *Endpoint
	AllowedIPs          []Address
	PersistentKeepalive uint16 //0 = off
}

//WirewrapSection holds the data from the [Wirewrap] section of the config file.
type WirewrapSection struct {
	ID            string
	EtcdEndpoints []Endpoint
}
