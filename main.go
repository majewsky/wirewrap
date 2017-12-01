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

package main

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"os/signal"
	"sync"
	"syscall"

	"github.com/majewsky/wirewrap/pkg/config"
	"github.com/majewsky/wirewrap/pkg/util"
	"github.com/majewsky/wirewrap/pkg/wirewrap"
)

func main() {
	if len(os.Args) != 2 {
		util.LogFatal("usage: wirewrap <config-file>")
	}

	//read configuration file
	cfg, err := config.FromFile(os.Args[1])
	if err != nil {
		util.LogFatal(err.Error())
	}

	//standard incantation for responding to interrupt signals
	ctx, cancel := context.WithCancel(context.Background())
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigc
		util.LogInfo("Received interrupt, shutting down...")
		cancel()
	}()
	var wg sync.WaitGroup

	//ensure that fatal errors, i.e. util.LogFatal(), shuts the application down
	//cleanly (servers esp. need to resign from the leader election explicitly to
	//minimize downtime)
	exitCode := 0
	util.TerminateHook = func() {
		util.LogInfo("Shutting down because of previous fatal error...")
		cancel()
		exitCode = 1
		wg.Wait()
	}

	//on servers, connect to etcd cluster (and check if that works before doing
	//anything else)
	if cfg.Wirewrap.ID != "" {
		//determine our own public key to participate in a leader election
		cmd := exec.Command("wg", "pubkey")
		cmd.Stdin = bytes.NewReader([]byte(cfg.Interface.PrivateKey.String()))
		var buf bytes.Buffer
		cmd.Stdout = &buf
		cmd.Stderr = os.Stderr
		err := cmd.Run()
		if err != nil {
			util.LogFatal("exec `wg pubkey` failed: " + err.Error())
		}

		//check that the generated public key is valid
		publicKey, err := config.KeyFromString(string(buf.Bytes()))
		if err != nil {
			util.LogFatal(err.Error())
		}
		electionChan, err := wirewrap.GoElectLeader(ctx, &wg, cfg.Wirewrap, publicKey.String())
		if err != nil {
			util.LogFatal(err.Error())
		}

		//DEBUG - TODO delete
		go func() {
			for result := range electionChan {
				util.LogInfo("leader elected for %s: %s", result.ID, result.PublicKey)
			}
		}()

	}

	<-ctx.Done()
	wg.Wait()
	os.Exit(exitCode)
}
