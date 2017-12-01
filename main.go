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
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/majewsky/wirewrap/pkg/config"
	"github.com/majewsky/wirewrap/pkg/util"
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
		cancel()
	}()

	_ = cfg
	<-ctx.Done()
}
