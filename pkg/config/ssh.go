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
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
)

//EncodeToOpenSSHPublicKey encodes this key as an OpenSSH ed25519 public key.
//The comment field contains the given string, or "wirewrap" if that string is
//empty.
func (k Key) EncodeToOpenSSHPublicKey(comment string) string {
	if comment == "" {
		comment = "wirewrap"
	}
	out := base64.StdEncoding.EncodeToString(sshEncodePublicKey(k))
	return "ssh-ed25519 " + out + " " + comment
}

//EncodeToOpenSSHPrivateKey encodes this keypair as an *unencrypted* OpenSSH
//ed25519 private key. The comment field of the public key contains the given
//string, or "wirewrap" if that string is empty.
func (p KeyPair) EncodeToOpenSSHPrivateKey(comment string) string {
	if comment == "" {
		comment = "wirewrap"
	}
	out := base64.StdEncoding.EncodeToString(sshEncodePrivateKey(p, comment))
	return "-----BEGIN OPENSSH PRIVATE KEY-----\n" + wrapAtColumn70(out) + "\n-----END OPENSSH PRIVATE KEY-----\n"
}

////////////////////////////////////////////////////////////////////////////////
//NOTE: No error reporting throughout this whole section, since the writers are
//all bytes.Buffer instances that have no meaningful failure mode (except OOM
//of course).

type sshBuffer struct {
	bytes.Buffer
}

//Write a bytestring into the io.Writer using the encoding for variable-length
//strings used by SSH.
func (b *sshBuffer) WriteField(text []byte) {
	binary.Write(b, binary.BigEndian, uint32(len(text)))
	b.Write(text)
}
func (b *sshBuffer) WriteFieldString(text string) {
	b.WriteField([]byte(text))
}

func sshEncodePublicKey(key Key) []byte {
	var buf sshBuffer
	buf.WriteFieldString("ssh-ed25519")
	buf.WriteField(key[:])
	return buf.Bytes()
}

func sshEncodePrivateKey(pair KeyPair, comment string) []byte {
	var buf sshBuffer

	buf.Write([]byte("openssh-key-v1\000"))
	buf.WriteFieldString("none") //cipher
	buf.WriteFieldString("none") //kdfname
	buf.WriteFieldString("")     //kdfoptions

	binary.Write(&buf, binary.BigEndian, uint32(1))    //number of public keys
	buf.WriteField(sshEncodePublicKey(pair.PublicKey)) //public key
	buf.WriteField(sshEncodeKeypair(pair, comment))    //keypair

	return buf.Bytes()
}

func sshEncodeKeypair(pair KeyPair, comment string) []byte {
	//at the start of the keypair are 8 random bytes (or actually 4 random bytes,
	//repeated twice) to add some randomness which (if I understand it correctly)
	//is useful when the keypair is stored encrypted to avoid known-plaintext
	//attacks; the manpage of ssh-keygen says that this particular private-keyfile
	//format "has increased resistance to brute-force password cracking")
	var randomBytes [4]byte
	_, err := rand.Read(randomBytes[:])
	if err != nil {
		panic("cannot get random bytes: " + err.Error())
	}
	var buf sshBuffer
	buf.Write(randomBytes[:])
	buf.Write(randomBytes[:])

	//write public key
	buf.Write(sshEncodePublicKey(pair.PublicKey))

	//write private key (includes the public key for ssh-ed25519)
	var keyConcatenation [64]byte
	copy(keyConcatenation[0:32], pair.PrivateKey[:])
	copy(keyConcatenation[32:], pair.PublicKey[:])
	buf.WriteField(keyConcatenation[:])

	//write comment field
	buf.WriteFieldString(comment)

	//pad to 8-byte boundary
	var padByte byte
	for buf.Len()%8 != 0 {
		padByte++
		buf.WriteByte(padByte)
	}
	return buf.Bytes()
}

////////////////////////////////////////////////////////////////////////////////

func wrapAtColumn70(text string) string {
	if len(text) <= 70 {
		return text
	}
	return text[0:70] + "\n" + wrapAtColumn70(text[70:])
}
