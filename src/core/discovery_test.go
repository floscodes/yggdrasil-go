package core

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/url"
	"testing"
	"time"

	"github.com/yggdrasil-network/yggdrasil-go/src/config"
)

func TestDiscoveryValidation(t *testing.T) {
	valid := config.DiscoveryService{Name: "wiki", Address: "300::1", Port: 80, Protocol: "tcp"}
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
			if validateDiscoveryServices([]config.DiscoveryService{s}) == nil {
				t.Fatal("accepted invalid service")
			}
		})
	}
	if err := validateDiscoveryServices([]config.DiscoveryService{valid}); err != nil {
		t.Fatal(err)
	}
	if validateDiscoveryServices([]config.DiscoveryService{valid, valid}) == nil {
		t.Fatal("accepted duplicate names")
	}
}

func discoveryTestNode(t *testing.T, enabled, forward bool, services ...config.DiscoveryService) *Core {
	t.Helper()
	cfg := config.GenerateConfig()
	if err := cfg.GenerateSelfSignedCertificate(); err != nil {
		t.Fatal(err)
	}
	c, err := New(cfg.Certificate, nil, Discovery{Enabled: enabled, Forward: forward, Services: services})
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
			publisher.config.discovery.Services = []config.DiscoveryService{{Name: "wiki", Address: "300::1", Port: 80, Protocol: "tcp"}}
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
			if len(b.GetServices().Services) != 0 {
				t.Fatal("accepted forged signature")
			}
			a.discovery.send(keyArray(b.public), record.wire)
			if tc.enabled {
				discoveryWait(t, func() bool {
					a.discovery.send(keyArray(b.public), record.wire)
					return len(b.GetServices().Services) == 1
				})
			}
			if tc.want {
				discoveryWait(t, func() bool { return len(c.GetServices().Services) == 1 })
				if len(a.GetServices().Services) != 0 {
					t.Fatal("announcement returned to incoming peer")
				}
				// Replay and older snapshots must not change or multiply results.
				a.discovery.send(keyArray(b.public), record.wire)
				older, _ := d.announce(time.Now().Add(-time.Minute))
				a.discovery.send(keyArray(b.public), older.wire)
				time.Sleep(100 * time.Millisecond)
				if got := b.GetServices(); len(got.Services) != 1 || !got.Services[0].Expires.Equal(time.Unix(record.payload.Issued, 0).Add(discoveryLifetime)) {
					t.Fatal("replay replaced announcement")
				}
				// Empty snapshots withdraw all services for this publisher.
				publisher.config.discovery.Services = nil
				withdrawal, _ := d.announce(time.Now().Add(time.Second))
				a.discovery.send(keyArray(b.public), withdrawal.wire)
				discoveryWait(t, func() bool { return len(b.GetServices().Services) == 0 && len(c.GetServices().Services) == 0 })
			} else {
				time.Sleep(200 * time.Millisecond)
				if len(c.GetServices().Services) != 0 {
					t.Fatal("unexpected forwarding")
				}
				if !tc.enabled && len(b.GetServices().Services) != 0 {
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
	service := config.DiscoveryService{Name: "wiki", Address: "300::1", Port: 80, Protocol: "tcp"}
	a := discoveryTestNode(t, true, false, service)
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
		services := b.GetServices().Services
		if len(services) == 1 && services[0].DiscoveryService == service {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("configured service was not automatically advertised to the new peer")
}
