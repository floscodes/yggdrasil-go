package core

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/netip"
	"net/url"
	"testing"
	"testing/synctest"
	"time"

	"github.com/yggdrasil-network/yggdrasil-go/src/address"
	"github.com/yggdrasil-network/yggdrasil-go/src/config"
)

func discoveryTestAddress(public ed25519.PublicKey) string {
	return netip.AddrFrom16([16]byte(*address.AddrForKey(public))).String()
}

func discoveryTestSubnetAddress(public ed25519.PublicKey) string {
	var bytes [16]byte
	copy(bytes[:], address.SubnetForKey(public)[:])
	bytes[15] = 1
	return netip.AddrFrom16(bytes).String()
}

func TestDiscoveryValidation(t *testing.T) {
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	valid := config.DiscoveryService{Name: "wiki", Address: discoveryTestAddress(public), Port: 80, Protocol: config.DiscoveryProtocolTCP}
	for _, tc := range []struct {
		name   string
		change func(*config.DiscoveryService)
	}{
		{"empty name", func(s *config.DiscoveryService) { s.Name = "" }},
		{"control character", func(s *config.DiscoveryService) { s.Name = "wiki\n" }},
		{"IPv4", func(s *config.DiscoveryService) { s.Address = "127.0.0.1" }},
		{"outside overlay", func(s *config.DiscoveryService) { s.Address = "2001:db8::1" }},
		{"no port", func(s *config.DiscoveryService) { s.Port = 0 }},
		{"unknown protocol", func(s *config.DiscoveryService) { s.Protocol = "http" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := valid
			tc.change(&s)
			if validateDiscoveryServices([]config.DiscoveryService{s}, public) == nil {
				t.Fatal("accepted invalid service")
			}
		})
	}
	if err := validateDiscoveryServices([]config.DiscoveryService{valid}, public); err != nil {
		t.Fatal(err)
	}
	udp := valid
	udp.Protocol = config.DiscoveryProtocolTCPUDP
	if err := validateDiscoveryServices([]config.DiscoveryService{udp}, public); err != nil {
		t.Fatal(err)
	}
	udp.Protocol = config.DiscoveryProtocolUDP
	if err := validateDiscoveryServices([]config.DiscoveryService{udp}, public); err != nil {
		t.Fatal(err)
	}
	if validateDiscoveryServices([]config.DiscoveryService{valid, valid}, public) == nil {
		t.Fatal("accepted duplicate names")
	}
}

func discoveryTestNode(t *testing.T, enabled, forward bool, services ...config.DiscoveryService) *Core {
	t.Helper()
	return discoveryTestNodeConfigured(t, Discovery{Enabled: enabled, Forward: forward, Services: services})
}

func discoveryTestNodeConfigured(t *testing.T, options Discovery) *Core {
	t.Helper()
	cfg := config.GenerateConfig()
	if err := cfg.GenerateSelfSignedCertificate(); err != nil {
		t.Fatal(err)
	}
	// Empty addresses in test fixtures mean this node's derived address.
	for i := range options.Services {
		if options.Services[i].Address == "" {
			options.Services[i].Address = discoveryTestAddress(cfg.Certificate.PrivateKey.(ed25519.PrivateKey).Public().(ed25519.PublicKey))
		}
	}
	c, err := New(cfg.Certificate, nil, options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Stop)
	go func() {
		buf := make([]byte, 65535)
		for {
			if _, _, err := c.ReadFrom(buf); err != nil {
				return
			}
		}
	}()
	return c
}

func discoveryConnect(t *testing.T, a, b *Core) {
	t.Helper()
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
	if !WaitConnected(a, b) {
		t.Fatal("routing did not converge")
	}
	// Establish an encrypted session before testing individual, non-retried
	// relay packets. Routing convergence alone does not complete this handshake.
	sender, receiver := a, b
	if !receiver.config.discovery.Enabled {
		sender, receiver = b, a
	}
	if receiver.config.discovery.Enabled {
		warmup, err := sender.discovery.announce(time.Now())
		if err != nil {
			t.Fatal(err)
		}
		discoveryWait(t, func() bool {
			sender.discovery.send(keyArray(receiver.public), warmup.wire)
			receiver.discovery.mu.Lock()
			defer receiver.discovery.mu.Unlock()
			_, ok := receiver.discovery.records[keyArray(sender.public)]
			return ok
		})
	}
}

func discoveryWait(t *testing.T, f func() bool) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if f() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("timed out waiting for discovery")
}

func TestDiscoveryRelay(t *testing.T) {
	for _, tc := range []struct {
		name                   string
		enabled, forward, want bool
	}{
		{"forward", true, true, true}, {"local only", true, false, false}, {"disabled", false, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := discoveryTestNode(t, true, false)
			b := discoveryTestNode(t, tc.enabled, tc.forward)
			c := discoveryTestNode(t, true, false)
			discoveryConnect(t, a, b)
			discoveryConnect(t, b, c)
			// Use a separate publisher to exercise verification of relayed origin signatures.
			public, secret, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			publisher := &Core{public: public, secret: secret}
			publisher.config.discovery.Services = []config.DiscoveryService{{Name: "wiki", Address: discoveryTestAddress(public), Port: 80, Protocol: config.DiscoveryProtocolTCP}}
			d := serviceDiscovery{core: publisher}
			record, err := d.announce(time.Now())
			if err != nil {
				t.Fatal(err)
			}
			// Forged announcements must never enter the cache.
			var forged discoveryAnnouncement
			if err = json.Unmarshal(record.wire, &forged); err != nil {
				t.Fatal(err)
			}
			forged.Signature[0] ^= 1
			wire, _ := json.Marshal(forged)
			a.discovery.send(keyArray(b.public), wire)
			time.Sleep(100 * time.Millisecond)
			if len(b.GetServices()) != 0 {
				t.Fatal("accepted forged signature")
			}
			a.discovery.send(keyArray(b.public), record.wire)
			if tc.enabled {
				discoveryWait(t, func() bool {
					a.discovery.send(keyArray(b.public), record.wire)
					return len(b.GetServices()) == 1
				})
			}
			if tc.want {
				discoveryWait(t, func() bool { return len(c.GetServices()) == 1 })
				if len(a.GetServices()) != 0 {
					t.Fatal("announcement returned to incoming peer")
				}
				// Replay and older snapshots must not change or multiply results.
				a.discovery.send(keyArray(b.public), record.wire)
				older, _ := d.announce(time.Now().Add(-time.Minute))
				a.discovery.send(keyArray(b.public), older.wire)
				time.Sleep(100 * time.Millisecond)
				if got := b.GetServices(); len(got) != 1 || !got[0].Expires.Equal(time.Unix(record.payload.Issued, 0).Add(discoveryLifetime)) {
					t.Fatal("replay replaced announcement")
				}
				// Empty snapshots withdraw all services for this publisher.
				publisher.config.discovery.Services = nil
				withdrawal, _ := d.announce(time.Now().Add(time.Second))
				a.discovery.send(keyArray(b.public), withdrawal.wire)
				discoveryWait(t, func() bool {
					a.discovery.send(keyArray(b.public), withdrawal.wire)
					return len(b.GetServices()) == 0 && len(c.GetServices()) == 0
				})
			} else {
				time.Sleep(200 * time.Millisecond)
				if len(c.GetServices()) != 0 {
					t.Fatal("unexpected forwarding")
				}
				if !tc.enabled && len(b.GetServices()) != 0 {
					t.Fatal("disabled discovery accepted announcement")
				}
			}
		})
	}
}

func TestDiscoveryExpiry(t *testing.T) {
	d := serviceDiscovery{records: map[keyArray]discoveryRecord{{1}: {payload: discoveryPayload{Issued: time.Now().Add(-discoveryLifetime).Unix()}}}}
	d.cleanup(time.Now())
	if len(d.records) != 0 {
		t.Fatal("expired announcement retained")
	}
}

// Exercise automatic announcements to a peer added after startup, without
// injecting a packet or warming up encrypted sessions in the test.
func TestDiscoveryAutomaticAnnouncement(t *testing.T) {
	service := config.DiscoveryService{Name: "wiki", Port: 80, Protocol: config.DiscoveryProtocolTCP}
	a := discoveryTestNode(t, true, false, service)
	service.Address = discoveryTestAddress(a.public)
	b := discoveryTestNode(t, true, false)
	u, _ := url.Parse("tcp://127.0.0.1:0")
	listener, err := b.Listen(u, "")
	if err != nil {
		t.Fatal(err)
	}
	u, _ = url.Parse("tcp://" + listener.Addr().String())
	if err = a.CallPeer(u, ""); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		services := b.GetServices()
		if len(services) == 1 && services[0].DiscoveryService == service {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("configured service was not automatically advertised to the new peer")
}

func TestDiscoveryRefreshInterval(t *testing.T) {
	for _, tc := range []struct {
		interval string
		want     time.Duration
	}{
		{"", 15 * time.Minute}, {"5m", 5 * time.Minute}, {"15m", 15 * time.Minute}, {"60m", 60 * time.Minute},
	} {
		t.Run(tc.interval, func(t *testing.T) {
			c := discoveryTestNodeConfigured(t, Discovery{RefreshInterval: tc.interval})
			if c.discovery.refreshInterval != tc.want {
				t.Fatalf("got %s, want %s", c.discovery.refreshInterval, tc.want)
			}
		})
	}
	for _, interval := range []string{"0s", "-1s", "1s", "4m59s", "60m1s", "invalid"} {
		t.Run(interval, func(t *testing.T) {
			cfg := config.GenerateConfig()
			if err := cfg.GenerateSelfSignedCertificate(); err != nil {
				t.Fatal(err)
			}
			c, err := New(cfg.Certificate, nil, Discovery{RefreshInterval: interval})
			if err == nil {
				c.Stop()
				t.Fatal("accepted invalid refresh interval")
			}
		})
	}
}

func TestDiscoveryConfiguredRefresh(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		public, secret, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		c := &Core{public: public, secret: secret, ctx: ctx}
		c.config.discovery = Discovery{Enabled: true, RefreshInterval: "5m", Services: []config.DiscoveryService{{Name: "wiki", Address: discoveryTestAddress(public), Port: 80, Protocol: config.DiscoveryProtocolTCP}}}
		if err := c.discovery.init(c); err != nil {
			t.Fatal(err)
		}
		go c.discovery.run()
		synctest.Wait()
		issued := func() int64 {
			c.discovery.mu.Lock()
			defer c.discovery.mu.Unlock()
			return c.discovery.records[keyArray(public)].payload.Issued
		}
		first := issued()
		time.Sleep(4 * time.Minute)
		synctest.Wait()
		if issued() != first {
			t.Fatal("refreshed too early")
		}
		time.Sleep(time.Minute)
		synctest.Wait()
		if got := issued(); got != first+300 {
			t.Fatalf("got timestamp %d, want %d", got, first+300)
		}
	})
}

func TestDiscoveryRenewal(t *testing.T) {
	newCore := func() *Core {
		public, secret, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		c := &Core{public: public, secret: secret}
		c.config.discovery = Discovery{Enabled: true}
		if err := c.discovery.init(c); err != nil {
			t.Fatal(err)
		}
		return c
	}
	publisher, receiver := newCore(), newCore()
	publisher.config.discovery.Services = []config.DiscoveryService{{Name: "dns", Address: discoveryTestAddress(publisher.public), Port: 53, Protocol: config.DiscoveryProtocolTCPUDP}}
	from := keyArray(publisher.public)
	disconnected := receiver.discovery.connected(from)
	defer disconnected()
	now := time.Now().Truncate(time.Second)
	first, err := publisher.discovery.announce(now.Add(-2 * time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	receiver.discovery.handle(from, first.wire)
	before := receiver.GetServices()
	if len(before) != 1 {
		t.Fatal("initial service missing")
	}
	renewed, err := publisher.discovery.announce(now.Add(-time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	receiver.discovery.handle(from, renewed.wire)
	after := receiver.GetServices()
	if len(after) != 1 || after[0].DiscoveryService != before[0].DiscoveryService || after[0].PublicKey != before[0].PublicKey {
		t.Fatal("renewal changed or duplicated the service")
	}
	if !after[0].Expires.Equal(now.Add(59 * time.Minute)) {
		t.Fatalf("unexpected expiry: %s", after[0].Expires)
	}
	receiver.discovery.cleanup(now.Add(58 * time.Minute))
	if len(receiver.discovery.records) != 1 {
		t.Fatal("expired before renewed lifetime")
	}
	receiver.discovery.cleanup(now.Add(59 * time.Minute))
	if len(receiver.discovery.records) != 0 {
		t.Fatal("did not expire sixty minutes after renewal")
	}
}

// Observe actual protocol packets rather than cache entries: duplicate delivery
// would be hidden by the receiver's normal deduplication.
func TestDiscoveryForwardOnce(t *testing.T) {
	a := discoveryTestNode(t, true, false)
	b := discoveryTestNode(t, false, false, config.DiscoveryService{Name: "relay", Port: 80, Protocol: config.DiscoveryProtocolTCP})
	// Accelerate the periodic sender for this test only. User configuration still
	// enforces the five-minute minimum. No links exist while setting up the core.
	b.config.discovery.Enabled = true
	b.config.discovery.Forward = true
	b.discovery.refreshInterval = 50 * time.Millisecond
	go b.discovery.run()
	public, secret, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publisher := &Core{public: public, secret: secret}
	publisher.config.discovery.Services = []config.DiscoveryService{{Name: "wiki", Address: discoveryTestAddress(public), Port: 80, Protocol: config.DiscoveryProtocolTCP}}
	announcements := serviceDiscovery{core: publisher}
	sink := func() (*Core, chan int64) {
		cfg := config.GenerateConfig()
		if err := cfg.GenerateSelfSignedCertificate(); err != nil {
			t.Fatal(err)
		}
		c, err := New(cfg.Certificate, nil, Discovery{Enabled: false})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(c.Stop)
		received := make(chan int64, 64)
		go func() {
			buf := make([]byte, 65535)
			for {
				n, _, err := c.PacketConn.ReadFrom(buf)
				if err != nil {
					return
				}
				if n < 2 || buf[0] != typeSessionProto || buf[1] != typeProtoDiscovery {
					continue
				}
				var wire discoveryAnnouncement
				var payload discoveryPayload
				if json.Unmarshal(buf[2:n], &wire) != nil || json.Unmarshal(wire.Payload, &payload) != nil {
					continue
				}
				if len(payload.Key) == ed25519.PublicKeySize && keyArray(payload.Key) == keyArray(public) {
					received <- payload.Issued
				}
			}
		}()
		return c, received
	}
	expect := func(ch chan int64, issued int64) {
		t.Helper()
		select {
		case got := <-ch:
			if got != issued {
				t.Fatalf("received timestamp %d, want %d", got, issued)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("missing forwarded announcement")
		}
	}
	quiet := func(ch chan int64) {
		t.Helper()
		select {
		case <-ch:
			t.Fatal("foreign announcement forwarded more than once or replayed to a new peer")
		case <-time.After(250 * time.Millisecond):
		}
	}
	c, received := sink()
	discoveryConnect(t, a, b)
	discoveryConnect(t, b, c)
	first, err := announcements.announce(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	b.discovery.handle(keyArray(a.public), first.wire)
	expect(received, first.payload.Issued)
	b.discovery.handle(keyArray(a.public), first.wire)
	quiet(received) // Includes several periodic refreshes.
	late, lateReceived := sink()
	discoveryConnect(t, b, late)
	quiet(lateReceived) // New peer synchronisation must not replay foreign records.
	quiet(received)
	renewal, err := announcements.announce(time.Now().Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	b.discovery.handle(keyArray(a.public), renewal.wire)
	b.discovery.handle(keyArray(a.public), renewal.wire)
	expect(received, renewal.payload.Issued)
	expect(lateReceived, renewal.payload.Issued)
	quiet(received)
	quiet(lateReceived)
}

func TestDiscoveryAddressOwnership(t *testing.T) {
	cfg := config.GenerateConfig()
	if err := cfg.GenerateSelfSignedCertificate(); err != nil {
		t.Fatal(err)
	}
	public := cfg.Certificate.PrivateKey.(ed25519.PrivateKey).Public().(ed25519.PublicKey)
	other, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ownIP := netip.MustParseAddr(discoveryTestAddress(public))
	for _, tc := range []struct {
		name, ip string
		valid    bool
	}{
		{"node address", ownIP.String(), true},
		{"routed device", discoveryTestSubnetAddress(public), true},
		{"other node", discoveryTestAddress(other), false},
		{"other subnet", discoveryTestSubnetAddress(other), false},
		{"adjacent node address", ownIP.Next().String(), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			service := config.DiscoveryService{Name: "wiki", Address: tc.ip, Port: 80, Protocol: config.DiscoveryProtocolTCP}
			c, err := New(cfg.Certificate, nil, Discovery{Enabled: true, Services: []config.DiscoveryService{service}})
			if tc.valid {
				if err != nil {
					t.Fatal(err)
				}
				c.Stop()
			} else if err == nil {
				c.Stop()
				t.Fatal("accepted a service outside the node's address and subnet")
			}
		})
	}
}

func TestDiscoveryRejectForeignEndpoints(t *testing.T) {
	public, secret, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	receiver := &Core{public: public, secret: secret}
	receiver.config.discovery = Discovery{Enabled: true, Forward: true}
	if err := receiver.discovery.init(receiver); err != nil {
		t.Fatal(err)
	}
	publisherKey, publisherSecret, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publisher := &Core{public: publisherKey, secret: publisherSecret}
	announcements := serviceDiscovery{core: publisher}
	relayKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	from := keyArray(relayKey)
	disconnect := receiver.discovery.connected(from)
	defer disconnect()
	// Another connected peer ensures invalid records cannot reach forwarding.
	// The fake core deliberately has no PacketConn: forwarding would fail the test.
	disconnectOther := receiver.discovery.connected(keyArray(public))
	defer disconnectOther()
	for _, ip := range []string{discoveryTestAddress(public), discoveryTestSubnetAddress(public), discoveryTestAddress(relayKey)} {
		publisher.config.discovery.Services = []config.DiscoveryService{{Name: "forged-endpoint", Address: ip, Port: 80, Protocol: config.DiscoveryProtocolTCP}}
		record, err := announcements.announce(time.Now())
		if err != nil {
			t.Fatal(err)
		}
		receiver.discovery.handle(from, record.wire)
		if len(receiver.discovery.records) != 0 {
			t.Fatal("accepted a signed announcement advertising another key's endpoint")
		}
	}
	// The publisher's routed device is valid even when the immediate relay has
	// a different key: ownership belongs to the signer, not the incoming peer.
	receiver.config.discovery.Forward = false
	publisher.config.discovery.Services[0].Address = discoveryTestSubnetAddress(publisherKey)
	record, err := announcements.announce(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	receiver.discovery.handle(from, record.wire)
	if len(receiver.GetServices()) != 1 {
		t.Fatal("rejected valid routed endpoint from a relay")
	}
}

func TestDiscoveryEmptyServicesSilent(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		public, secret, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		c := &Core{public: public, secret: secret, ctx: ctx}
		c.config.discovery = Discovery{Enabled: true, Forward: true}
		if err := c.discovery.init(c); err != nil {
			t.Fatal(err)
		}
		// A connected peer and no PacketConn make any attempted announcement fail.
		// Advance past multiple refresh intervals and the full cache lifetime.
		disconnect := c.discovery.connected(keyArray{1})
		defer disconnect()
		go c.discovery.run()
		synctest.Wait()
		time.Sleep(61 * time.Minute)
		synctest.Wait()
		c.discovery.mu.Lock()
		defer c.discovery.mu.Unlock()
		if len(c.discovery.records) != 0 {
			t.Fatal("created an own announcement without services")
		}
	})
}

func TestDiscoveryCoreDefaults(t *testing.T) {
	cfg := config.GenerateConfig()
	c, err := New(cfg.Certificate, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Stop()
	if !c.config.discovery.Enabled || !c.config.discovery.Forward || len(c.config.discovery.Services) != 0 {
		t.Fatal("unexpected discovery defaults")
	}
}
