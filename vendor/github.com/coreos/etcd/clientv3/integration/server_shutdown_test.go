// Copyright 2017 The etcd Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package integration

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/coreos/etcd/clientv3"
	"github.com/coreos/etcd/etcdserver/api/v3rpc/rpctypes"
	"github.com/coreos/etcd/integration"
	"github.com/coreos/etcd/pkg/testutil"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TestBalancerUnderServerShutdownWatch expects that watch client
// switch its endpoints when the member of the pinned endpoint fails.
func TestBalancerUnderServerShutdownWatch(t *testing.T) {
	defer testutil.AfterTest(t)

	clus := integration.NewClusterV3(t, &integration.ClusterConfig{
		Size:               3,
		SkipCreatingClient: true,
	})
	defer clus.Terminate(t)

	eps := []string{clus.Members[0].GRPCAddr(), clus.Members[1].GRPCAddr(), clus.Members[2].GRPCAddr()}

	lead := clus.WaitLeader(t)

	// pin eps[lead]
	watchCli, err := clientv3.New(clientv3.Config{Endpoints: []string{eps[lead]}})
	if err != nil {
		t.Fatal(err)
	}
	defer watchCli.Close()

	// wait for eps[lead] to be pinned
	mustWaitPinReady(t, watchCli)

	// add all eps to list, so that when the original pined one fails
	// the client can switch to other available eps
	watchCli.SetEndpoints(eps...)

	key, val := "foo", "bar"
	wch := watchCli.Watch(context.Background(), key, clientv3.WithCreatedNotify())
	select {
	case <-wch:
	case <-time.After(3 * time.Second):
		t.Fatal("took too long to create watch")
	}

	donec := make(chan struct{})
	go func() {
		defer close(donec)

		// switch to others when eps[lead] is shut down
		select {
		case ev := <-wch:
			if werr := ev.Err(); werr != nil {
				t.Fatal(werr)
			}
			if len(ev.Events) != 1 {
				t.Fatalf("expected one event, got %+v", ev)
			}
			if !bytes.Equal(ev.Events[0].Kv.Value, []byte(val)) {
				t.Fatalf("expected %q, got %+v", val, ev.Events[0].Kv)
			}
		case <-time.After(7 * time.Second):
			t.Fatal("took too long to receive events")
		}
	}()

	// shut down eps[lead]
	clus.Members[lead].Terminate(t)

	// writes to eps[lead+1]
	putCli, err := clientv3.New(clientv3.Config{Endpoints: []string{eps[(lead+1)%3]}})
	if err != nil {
		t.Fatal(err)
	}
	defer putCli.Close()
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_, err = putCli.Put(ctx, key, val)
		cancel()
		if err == nil {
			break
		}
		if err == context.DeadlineExceeded || isServerCtxTimeout(err) || err == rpctypes.ErrTimeout || err == rpctypes.ErrTimeoutDueToLeaderFail {
			continue
		}
		t.Fatal(err)
	}

	select {
	case <-donec:
	case <-time.After(5 * time.Second): // enough time for balancer switch
		t.Fatal("took too long to receive events")
	}
}

func TestBalancerUnderServerShutdownPut(t *testing.T) {
	testBalancerUnderServerShutdownMutable(t, func(cli *clientv3.Client, ctx context.Context) error {
		_, err := cli.Put(ctx, "foo", "bar")
		return err
	})
}

func TestBalancerUnderServerShutdownDelete(t *testing.T) {
	testBalancerUnderServerShutdownMutable(t, func(cli *clientv3.Client, ctx context.Context) error {
		_, err := cli.Delete(ctx, "foo")
		return err
	})
}

func TestBalancerUnderServerShutdownTxn(t *testing.T) {
	testBalancerUnderServerShutdownMutable(t, func(cli *clientv3.Client, ctx context.Context) error {
		_, err := cli.Txn(ctx).
			If(clientv3.Compare(clientv3.Version("foo"), "=", 0)).
			Then(clientv3.OpPut("foo", "bar")).
			Else(clientv3.OpPut("foo", "baz")).Commit()
		return err
	})
}

// testBalancerUnderServerShutdownMutable expects that when the member of
// the pinned endpoint is shut down, the balancer switches its endpoints
// and all subsequent put/delete/txn requests succeed with new endpoints.
func testBalancerUnderServerShutdownMutable(t *testing.T, op func(*clientv3.Client, context.Context) error) {
	defer testutil.AfterTest(t)

	clus := integration.NewClusterV3(t, &integration.ClusterConfig{
		Size:               3,
		SkipCreatingClient: true,
	})
	defer clus.Terminate(t)

	eps := []string{clus.Members[0].GRPCAddr(), clus.Members[1].GRPCAddr(), clus.Members[2].GRPCAddr()}

	// pin eps[0]
	cli, err := clientv3.New(clientv3.Config{Endpoints: []string{eps[0]}})
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()

	// wait for eps[0] to be pinned
	mustWaitPinReady(t, cli)

	// add all eps to list, so that when the original pined one fails
	// the client can switch to other available eps
	cli.SetEndpoints(eps...)

	// shut down eps[0]
	clus.Members[0].Terminate(t)

	// switched to others when eps[0] was explicitly shut down
	// and following request should succeed
	// TODO: remove this (expose client connection state?)
	time.Sleep(time.Second)

	cctx, ccancel := context.WithTimeout(context.Background(), time.Second)
	err = op(cli, cctx)
	ccancel()
	if err != nil {
		t.Fatal(err)
	}
}

func TestBalancerUnderServerShutdownGetLinearizable(t *testing.T) {
	testBalancerUnderServerShutdownImmutable(t, func(cli *clientv3.Client, ctx context.Context) error {
		_, err := cli.Get(ctx, "foo")
		return err
	}, 7*time.Second) // give enough time for leader election, balancer switch
}

func TestBalancerUnderServerShutdownGetSerializable(t *testing.T) {
	testBalancerUnderServerShutdownImmutable(t, func(cli *clientv3.Client, ctx context.Context) error {
		_, err := cli.Get(ctx, "foo", clientv3.WithSerializable())
		return err
	}, 2*time.Second)
}

// testBalancerUnderServerShutdownImmutable expects that when the member of
// the pinned endpoint is shut down, the balancer switches its endpoints
// and all subsequent range requests succeed with new endpoints.
func testBalancerUnderServerShutdownImmutable(t *testing.T, op func(*clientv3.Client, context.Context) error, timeout time.Duration) {
	defer testutil.AfterTest(t)

	clus := integration.NewClusterV3(t, &integration.ClusterConfig{
		Size:               3,
		SkipCreatingClient: true,
	})
	defer clus.Terminate(t)

	eps := []string{clus.Members[0].GRPCAddr(), clus.Members[1].GRPCAddr(), clus.Members[2].GRPCAddr()}

	// pin eps[0]
	cli, err := clientv3.New(clientv3.Config{Endpoints: []string{eps[0]}})
	if err != nil {
		t.Errorf("failed to create client: %v", err)
	}
	defer cli.Close()

	// wait for eps[0] to be pinned
	mustWaitPinReady(t, cli)

	// add all eps to list, so that when the original pined one fails
	// the client can switch to other available eps
	cli.SetEndpoints(eps...)

	// shut down eps[0]
	clus.Members[0].Terminate(t)

	// switched to others when eps[0] was explicitly shut down
	// and following request should succeed
	cctx, ccancel := context.WithTimeout(context.Background(), timeout)
	err = op(cli, cctx)
	ccancel()
	if err != nil {
		t.Errorf("failed to finish range request in time %v (timeout %v)", err, timeout)
	}
}

// e.g. due to clock drifts in server-side,
// client context times out first in server-side
// while original client-side context is not timed out yet
func isServerCtxTimeout(err error) bool {
	if err == nil {
		return false
	}
	ev, _ := status.FromError(err)
	code := ev.Code()
	return code == codes.DeadlineExceeded && strings.Contains(err.Error(), "context deadline exceeded")
}
