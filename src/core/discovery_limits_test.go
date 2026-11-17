package core

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yggdrasil-network/yggdrasil-go/src/config"
)

// Synchronous test harness; production has exactly one bounded verification worker.
func (d *serviceDiscovery) handle(from keyArray, wire []byte) {
	if d.admit(from, wire) {
		d.process(from, wire)
	}
}

// No background workers: tests control queue saturation and admission deterministically.
func discoveryBare(t *testing.T, services bool) *Core {
	t.Helper()
	pub, secret, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	c := &Core{public: pub, secret: secret, ctx: ctx, cancel: cancel}
	c.config.discovery = Discovery{Enabled: true}
	if services {
		c.config.discovery.Services = []config.DiscoveryService{{Name: "wiki", Address: discoveryTestAddress(pub), Port: 80, Protocol: config.DiscoveryProtocolTCP}}
	}
	if err = c.discovery.init(c); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestDiscoveryPacketBoundaries(t *testing.T) {
	receiver, publisher := discoveryBare(t, false), discoveryBare(t, true)
	from := keyArray(publisher.public)
	defer receiver.discovery.connected(from)()
	record, err := publisher.discovery.announce(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	// Outer trailing JSON whitespace leaves the signed raw payload unchanged.
	exact := append(bytes.Clone(record.wire), bytes.Repeat([]byte(" "), discoveryMaxPacket-len(record.wire))...)
	oversized := append(bytes.Clone(exact), ' ')
	receiver.discovery.handle(from, oversized)
	if len(receiver.GetServices()) != 0 {
		t.Fatal("oversized body was cached")
	}
	receiver.discovery.handle(from, exact)
	if len(receiver.GetServices()) != 1 {
		t.Fatal("8192-byte body was rejected")
	}
	for _, tc := range []struct {
		size  int
		mtu   uint64
		valid bool
	}{
		{8192, 8194, true}, {8193, 10000, false}, {8192, 8193, false},
	} {
		if got := validateDiscoveryPacketSize(tc.size, tc.mtu); (got == nil) != tc.valid {
			t.Fatalf("size=%d mtu=%d: %v", tc.size, tc.mtu, got)
		}
	}
}

func TestDiscoverySerializedAndServiceLimits(t *testing.T) {
	c := discoveryBare(t, true)
	base := c.config.discovery.Services[0]
	for _, tc := range []struct {
		name   string
		count  int
		suffix string
		valid  bool
	}{
		{"32 long names", 32, strings.Repeat("a", 126), true},
		{"33 services", 33, "wiki", false},
		{"escaped names exceed envelope", 10, strings.Repeat("<", 126), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			services := make([]config.DiscoveryService, tc.count)
			for i := range services {
				services[i] = base
				services[i].Name = fmt.Sprintf("%02d%s", i, tc.suffix)
			}
			c.config.discovery.Services = services
			validation := validateDiscoveryServices(services, c.public)
			var err error
			if validation == nil {
				_, err = c.discovery.announce(time.Now())
			} else {
				err = validation
			}
			if (err == nil) != tc.valid {
				t.Fatalf("unexpected result: %v", err)
			}
			// Startup checks the entire serialized snapshot too, without publishing a prefix.
			if err = c.discovery.init(c); (err == nil) != tc.valid {
				t.Fatalf("startup result: %v", err)
			}
		})
	}
	for _, tc := range []struct {
		name  string
		valid bool
	}{
		{strings.Repeat("ä", 64), true}, {strings.Repeat("ä", 64) + "a", false},
	} {
		s := base
		s.Name = tc.name
		if err := validateDiscoveryServices([]config.DiscoveryService{s}, c.public); (err == nil) != tc.valid {
			t.Fatalf("name bytes=%d: %v", len(tc.name), err)
		}
	}
}

func TestDiscoveryBuckets(t *testing.T) {
	now := time.Now()
	for _, tc := range []struct {
		name  string
		limit config.DiscoveryRateLimit
		size  int
	}{
		{"messages", config.DiscoveryRateLimit{MessagesPerMinute: 1, BytesPerMinute: 100, BurstMessages: 1, BurstBytes: 100}, 1},
		{"bytes", config.DiscoveryRateLimit{MessagesPerMinute: 100, BytesPerMinute: 10, BurstMessages: 100, BurstBytes: 10}, 10},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var b discoveryBucket
			if !b.allow(now, tc.size, tc.limit) || b.allow(now, tc.size, tc.limit) {
				t.Fatal("burst not enforced")
			}
			if !b.allow(now.Add(time.Minute), tc.size, tc.limit) {
				t.Fatal("budget did not refill")
			}
			if b.allow(now.Add(-time.Minute), tc.size, tc.limit) {
				t.Fatal("clock rollback refilled budget")
			}
		})
	}
	var global, peer discoveryBucket
	generous := config.DiscoveryRateLimit{MessagesPerMinute: 1, BytesPerMinute: 100, BurstMessages: 2, BurstBytes: 100}
	narrow := generous
	narrow.BurstMessages = 1
	if !discoveryAllow(now, 1, &global, generous, &peer, narrow) {
		t.Fatal("initial admission failed")
	}
	if discoveryAllow(now, 1, &global, generous, &peer, narrow) {
		t.Fatal("peer cap bypassed")
	}
	if global.messages != 1 {
		t.Fatal("throttled peer drained global budget")
	}
}

func TestDiscoveryRateConfiguration(t *testing.T) {
	defaults, err := discoveryLimits(config.DiscoveryRateLimits{})
	if err != nil || defaults.Publisher.MessagesPerMinute != 1 {
		t.Fatalf("defaults: %v", err)
	}
	for _, limits := range []config.DiscoveryRateLimits{
		{Ingress: config.DiscoveryRateLimit{MessagesPerMinute: -1}},
		{Egress: config.DiscoveryRateLimit{BurstBytes: 8193}},
	} {
		if _, err := discoveryLimits(limits); err == nil {
			t.Fatal("invalid rate configuration accepted")
		}
	}
	custom := config.DiscoveryRateLimits{PeerIngress: config.DiscoveryRateLimit{MessagesPerMinute: 12}}
	limits, err := discoveryLimits(custom)
	if err != nil || limits.PeerIngress.MessagesPerMinute != 12 || limits.PeerIngress.BurstMessages != defaults.PeerIngress.BurstMessages {
		t.Fatal("partial overrides lost")
	}
}

func TestDiscoveryIngressAndQueueBounds(t *testing.T) {
	c := discoveryBare(t, false)
	from := keyArray{1}
	disconnect := c.discovery.connected(from)
	// Same malformed envelope is still charged before JSON decoding.
	for i := 0; i < 1000; i++ {
		c.discovery.enqueue(from, []byte("invalid"))
	}
	status := c.GetDiscoveryStatus()
	if status.QueueDepth != discoveryQueueSize || status.QueueDrops == 0 || status.IngressDrops == 0 || status.VerificationAttempts != 0 {
		t.Fatalf("unbounded ingress: %+v", status)
	}
	// Distinct claimed identities in JSON have allocated no origin or limiter records.
	if len(c.discovery.records) != 0 || len(c.discovery.peerBudgets) != 1 {
		t.Fatal("unverified work allocated publisher state")
	}
	disconnect()
	if len(c.discovery.peerBudgets) != 0 {
		t.Fatal("disconnected peer retained limiter state")
	}
}

func TestDiscoveryPublisherBudgetAndForgery(t *testing.T) {
	c, p := discoveryBare(t, false), discoveryBare(t, true)
	from := keyArray(p.public)
	defer c.discovery.connected(from)()
	now := time.Now().Truncate(time.Second)
	first, _ := p.discovery.announce(now.Add(-10 * time.Second))
	c.discovery.handle(from, first.wire)
	var forged discoveryAnnouncement
	if err := json.Unmarshal(first.wire, &forged); err != nil {
		t.Fatal(err)
	}
	forged.Signature[0] ^= 1
	wire, _ := json.Marshal(forged)
	for i := 0; i < 20; i++ {
		c.discovery.handle(from, wire)
	}
	for i := 1; i <= 3; i++ {
		r, _ := p.discovery.announce(now.Add(time.Duration(i-10) * time.Second))
		c.discovery.handle(from, r.wire)
	}
	status := c.GetDiscoveryStatus()
	if status.PublisherDrops != 1 {
		t.Fatalf("publisher budget: %+v", status)
	}
	if got := c.discovery.records[from].payload.Issued; got != now.Unix()-8 {
		t.Fatalf("unexpected timestamp %d", got)
	}
	// Forged data neither advanced the record nor consumed its authenticated budget.
	record := c.discovery.records[from]
	record.budget.updated = now.Add(-time.Minute)
	c.discovery.records[from] = record
	next, _ := p.discovery.announce(now)
	c.discovery.handle(from, next.wire)
	if c.discovery.records[from].payload.Issued != now.Unix() {
		t.Fatal("valid renewal did not recover")
	}
}

func TestDiscoveryDuplicateFlood(t *testing.T) {
	c, p := discoveryBare(t, false), discoveryBare(t, true)
	from := keyArray(p.public)
	defer c.discovery.connected(from)()
	record, _ := p.discovery.announce(time.Now())
	// No background worker or traffic; the peer's finite burst caps verifications.
	c.discovery.limits.PeerIngress.MessagesPerMinute = 1
	for i := 0; i < 1000; i++ {
		c.discovery.handle(from, record.wire)
	}
	status := c.GetDiscoveryStatus()
	if status.IngressDrops == 0 || status.VerificationAttempts > uint64(c.discovery.limits.PeerIngress.BurstMessages) {
		t.Fatalf("unbounded verification: %+v", status)
	}
	if len(c.discovery.records) != 1 {
		t.Fatal("duplicates changed cache cardinality")
	}
}

func TestDiscoveryCapacityReservationAndExpiry(t *testing.T) {
	c, p := discoveryBare(t, true), discoveryBare(t, true)
	now := time.Now()
	// Seed a nearly full cache, then race actual signed updates and local publication.
	for i := 0; i < discoveryMaxOrigins-2; i++ {
		var key keyArray
		binary.LittleEndian.PutUint64(key[:], uint64(i+1))
		c.discovery.records[key] = discoveryRecord{payload: discoveryPayload{Issued: now.Unix()}}
	}
	from := keyArray(p.public)
	disconnectFrom := c.discovery.connected(from)
	defer func() {
		if disconnectFrom != nil {
			disconnectFrom()
		}
	}()
	r, _ := p.discovery.announce(now)
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Go(func() { c.discovery.handle(from, r.wire) })
	}
	wg.Wait()
	if len(c.discovery.records) != discoveryMaxOrigins-1 {
		t.Fatal("local slot not reserved")
	}
	other := discoveryBare(t, true)
	extra, _ := other.discovery.announce(now)
	c.discovery.handle(from, extra.wire)
	if c.GetDiscoveryStatus().CapacityDrops != 1 {
		t.Fatal("full foreign cache did not reject new publisher")
	}
	disconnectFrom()
	disconnectFrom = nil
	done := make(chan struct{})
	go func() { c.discovery.run(); close(done) }()
	discoveryWait(t, func() bool { return c.GetDiscoveryStatus().Publishers == discoveryMaxOrigins })
	c.cancel()
	<-done
	// The reserved slot has been populated; now expire all records without a worker racing us.
	c.discovery.mu.Lock()
	c.discovery.cleanup(now.Add(discoveryLifetime + time.Second))
	if len(c.discovery.records) != 0 {
		t.Fatal("expired slots retained")
	}
	c.discovery.mu.Unlock()
	defer c.discovery.connected(from)()
	c.discovery.handle(from, extra.wire)
	if c.GetDiscoveryStatus().Publishers != 1 {
		t.Fatal("expired capacity was not released")
	}
}

func TestDiscoveryApplicationProgressWithFullQueue(t *testing.T) {
	a := discoveryTestNode(t, true, false)
	cfg := config.GenerateConfig()
	b, err := New(cfg.Certificate, nil, Discovery{Enabled: false})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.Stop)
	// Start packet reading without a verification worker, then hold its queue full.
	b.config.discovery.Enabled = true
	for i := 0; i < cap(b.discovery.queue); i++ {
		b.discovery.queue <- discoveryJob{}
	}
	result := make(chan string, 1)
	go func() {
		buf := make([]byte, 65535)
		n, _, err := b.ReadFrom(buf)
		if err == nil {
			result <- string(buf[:n])
		}
	}()
	u, _ := url.Parse("tcp://127.0.0.1:0")
	listener, err := b.Listen(u, "")
	if err != nil {
		t.Fatal(err)
	}
	u, _ = url.Parse("tcp://" + listener.Addr().String())
	if err = a.CallPeer(u, ""); err != nil {
		t.Fatal(err)
	}
	discoveryWait(t, func() bool { return len(a.discovery.peers()) > 0 && len(b.discovery.peers()) > 0 })
	record, _ := a.discovery.announce(time.Now())
	deadline := time.After(10 * time.Second)
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case got := <-result:
			if got != "application" {
				t.Fatalf("unexpected payload %q", got)
			}
			if b.GetDiscoveryStatus().QueueDrops == 0 {
				t.Fatal("discovery queue was not exercised")
			}
			return
		case <-deadline:
			t.Fatal("application packet blocked behind discovery")
		case <-ticker.C:
			// During initial session setup Ironwood buffers only the latest message.
			// Wait until discovery has reached the full queue before sending application data.
			if b.GetDiscoveryStatus().QueueDrops == 0 {
				a.discovery.send(keyArray(b.public), record.wire)
			} else if _, err = a.WriteTo([]byte("application"), b.PacketConn.LocalAddr()); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestDiscoveryIngressGlobalAndByteBudgets(t *testing.T) {
	for _, dimension := range []string{"messages", "bytes"} {
		t.Run(dimension, func(t *testing.T) {
			c := discoveryBare(t, false)
			first, second := keyArray{1}, keyArray{2}
			defer c.discovery.connected(first)()
			defer c.discovery.connected(second)()
			c.discovery.limits.Ingress.MessagesPerMinute = 1
			c.discovery.limits.Ingress.BytesPerMinute = 1
			if dimension == "messages" {
				c.discovery.limits.Ingress.BurstMessages = 1
			} else {
				c.discovery.limits.Ingress.BurstBytes = 8
			}
			if !c.discovery.admit(first, []byte("bad-json")) {
				t.Fatal("first packet rejected")
			}
			if c.discovery.admit(second, []byte("bad-json")) {
				t.Fatal("global budget bypassed using another peer")
			}
			if c.GetDiscoveryStatus().IngressDrops != 1 {
				t.Fatal("global drop not reported")
			}
		})
	}
}

func TestDiscoveryEgressFanoutAndSendErrors(t *testing.T) {
	c := discoveryTestNode(t, false, false)
	d := &c.discovery
	d.limits.Egress.MessagesPerMinute = 1
	d.limits.PeerEgress.MessagesPerMinute = 1
	d.limits.Egress.BurstMessages = 2
	d.limits.PeerEgress.BurstMessages = 1
	first, second, third := keyArray{1}, keyArray{2}, keyArray{3}
	for _, peer := range []keyArray{first, second, third} {
		t.Cleanup(d.connected(peer))
	}
	d.send(first, []byte("{}"))
	d.send(first, []byte("{}")) // Per-peer budget.
	d.send(second, []byte("{}"))
	d.send(third, []byte("{}")) // Global budget includes each outgoing copy.
	status := c.GetDiscoveryStatus()
	if status.EgressDrops != 2 || status.SendErrors != 0 {
		t.Fatalf("egress budgets: %+v", status)
	}
	if err := c.PacketConn.Close(); err != nil {
		t.Fatal(err)
	}
	d.mu.Lock()
	d.egress = discoveryBucket{}
	d.peerBudgets[first].egress = discoveryBucket{}
	d.mu.Unlock()
	d.send(first, []byte("{}"))
	if c.GetDiscoveryStatus().SendErrors != 1 {
		t.Fatal("send error was swallowed")
	}
}
