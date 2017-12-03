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
	"os/exec"
	"strings"
	"testing"

	"github.com/majewsky/wirewrap/pkg/util"
)

func TestSSHEncoding(t *testing.T) {
	//To check the whole SSH key formatting shebang, encode a keypair as both
	//public and private key, and check if ssh-keygen produces the same public
	//key file when given the private key file that we generate.
	for idx, publicKey := range testKeysPublic {
		keypair := KeyPair{
			PrivateKey: testKeysPrivate[idx],
			PublicKey:  testKeysPublic[idx],
		}

		expected := publicKey.EncodeToOpenSSHPublicKey("wirewrap")
		//apparently `ssh-keygen -y` omits the comment field
		expected = strings.TrimSuffix(expected, " wirewrap")

		actual, err := util.CollectStdout(
			exec.Command("ssh-keygen", "-y", "-f", "/dev/stdin"),
			keypair.EncodeToOpenSSHPrivateKey("wirewrap"),
		)
		if err != nil {
			t.Error(err)
		}

		if strings.TrimSpace(actual) != strings.TrimSpace(expected) {
			t.Errorf(
				"unexpected output from `ssh-keygen -y` for test keypair %d/%d\n",
				idx+1, len(testKeysPublic),
			)
			t.Logf("expected: %s\n", expected)
			t.Logf("  actual: %s\n", actual)
		}
	}
}
