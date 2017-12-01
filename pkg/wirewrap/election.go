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

package wirewrap

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/coreos/etcd/clientv3"
	"github.com/coreos/etcd/clientv3/concurrency"
	"github.com/majewsky/wirewrap/pkg/config"
	"github.com/majewsky/wirewrap/pkg/util"
)

//Choice describes which peer (as described by its public key) can be used for a
//certain WirewrapID.
type Choice struct {
	ID        string
	PublicKey string
}

//GoElectLeader spawns a goroutine which participates in a leader election.
func GoElectLeader(ctx context.Context, wg *sync.WaitGroup, cfg config.WirewrapSection, ownPublicKey string) (<-chan Choice, error) {
	endpoints := make([]string, len(cfg.EtcdEndpoints))
	for idx, e := range cfg.EtcdEndpoints {
		endpoints[idx] = e.String()
	}

	util.LogInfo("Connecting to etcd at %s", strings.Join(endpoints, " and "))
	client, err := clientv3.New(clientv3.Config{
		Endpoints: endpoints,
	})
	if err != nil {
		return nil, err
	}

	keyForElection := fmt.Sprintf("/wirewrap/leader/%s",
		base64.URLEncoding.EncodeToString([]byte(cfg.ID)),
	)

	session, err := concurrency.NewSession(client)
	if err != nil {
		return nil, err
	}
	util.LogInfo("Participating in leader election at etcd key %s", keyForElection)
	election := concurrency.NewElection(session, keyForElection)
	if err != nil {
		return nil, err
	}

	//start the observer with a new context.Context and sync.WaitGroup; the
	//campaigner will use this to shut down the observer before tearing down
	//itself
	observerCtx, cancelObserver := context.WithCancel(context.Background())
	observerWg := &sync.WaitGroup{}

	resultChan := make(chan Choice, 1)
	observerWg.Add(1)
	go func() {
		defer observerWg.Done()

		var currentPublicKey string
		for resp := range election.Observe(observerCtx) {
			for _, kv := range resp.Kvs {
				newPublicKey := string(kv.Value)
				if newPublicKey != currentPublicKey {
					util.LogDebug("Observed leader election result: %s", newPublicKey)
					resultChan <- Choice{cfg.ID, newPublicKey}
					currentPublicKey = newPublicKey
				}
			}
		}
	}()

	//run the campaigner thread
	wg.Add(1)
	go func() {
		defer wg.Done()

		for ctx.Err() == nil {
			util.LogInfo("Campaigning for %s", ownPublicKey)
			err := election.Campaign(ctx, ownPublicKey)
			if err != nil && err != ctx.Err() {
				util.LogFatal("error while trying to participate in leader election: " + err.Error())
				continue
			}
			time.Sleep(5 * time.Second)
		}

		//we must wait for the observer to shut down before tearing down the election/session/client
		cancelObserver()
		observerWg.Wait()

		resignCtx, _ := context.WithTimeout(context.Background(), 5*time.Second)
		err := election.Resign(resignCtx)
		if err != nil {
			util.LogError("error while resigning from leader election: " + err.Error())
		}

		err = session.Close()
		if err != nil {
			util.LogError("error while closing leader election session: " + err.Error())
		}

		err = client.Close()
		if err != nil {
			util.LogError("error while closing etcd connection: " + err.Error())
		}

	}()

	return resultChan, nil
}
