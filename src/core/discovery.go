package core

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	iwt "github.com/Arceliar/ironwood/types"
	"github.com/yggdrasil-network/yggdrasil-go/src/address"
	"github.com/yggdrasil-network/yggdrasil-go/src/config"
)

// Discovery enables service announcements independently of multicast peer discovery.
type Discovery config.DiscoveryConfig

func (Discovery) isSetupOption() {}

const (
	discoveryMaxPacket = 8192
	// Bound the number of cached service entries per publisher, independently of bytes.
	discoveryMaxServices = 32
	discoveryMaxOrigins  = 1024
	discoveryLifetime    = 60 * time.Minute
	discoveryDomain      = "yggdrasil-service-discovery-v1\x00"
)

type discoveryPayload struct {
	Version  int
	Key      []byte
	Issued   int64
	Services []config.DiscoveryService
}

type discoveryAnnouncement struct {
	Payload   json.RawMessage
	Signature []byte
}

type discoveryRecord struct {
	payload discoveryPayload
	wire    []byte
}

type serviceDiscovery struct {
	core            *Core
	mu              sync.Mutex
	records         map[keyArray]discoveryRecord
	connections     map[keyArray]int
	refreshInterval time.Duration
}

// DiscoveredService is a signed advertisement, not a service availability check.
type DiscoveredService struct {
	config.DiscoveryService
	PublicKey string
	Expires   time.Time
}

type GetServicesResponse struct {
	Services []DiscoveredService
}

func validateDiscoveryServices(services []config.DiscoveryService, public ed25519.PublicKey) error {
	if len(public) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid publisher public key")
	}
	own := netip.AddrFrom16([16]byte(*address.AddrForKey(public)))
	var subnetBytes [16]byte
	copy(subnetBytes[:], address.SubnetForKey(public)[:])
	subnet := netip.PrefixFrom(netip.AddrFrom16(subnetBytes), 64)
	if len(services) > discoveryMaxServices {
		return fmt.Errorf("at most %d services are allowed", discoveryMaxServices)
	}
	names := make(map[string]bool)
	for _, s := range services {
		if s.Name == "" || len(s.Name) > 128 || !utf8.ValidString(s.Name) || strings.TrimSpace(s.Name) != s.Name || strings.IndexFunc(s.Name, unicode.IsControl) >= 0 {
			return fmt.Errorf("invalid service name %q", s.Name)
		}
		if names[s.Name] {
			return fmt.Errorf("duplicate service name %q", s.Name)
		}
		names[s.Name] = true
		ip, err := netip.ParseAddr(s.Address)
		if err != nil || !ip.Is6() || ip.Zone() != "" || (ip != own && !subnet.Contains(ip)) {
			return fmt.Errorf("service %q address %q must be the publisher address %s or belong to its routed subnet %s", s.Name, s.Address, own, subnet)
		}
		if s.Port == 0 || (s.Protocol != config.DiscoveryProtocolTCP && s.Protocol != config.DiscoveryProtocolUDP && s.Protocol != config.DiscoveryProtocolTCPUDP) {
			return fmt.Errorf("service %q requires a port and protocol tcp, udp or tcp+udp", s.Name)
		}
	}
	return nil
}

func (d *serviceDiscovery) init(c *Core) error {
	d.core = c
	interval := c.config.discovery.RefreshInterval
	if interval == "" {
		interval = config.DefaultDiscoveryRefreshInterval
	}
	parsed, err := time.ParseDuration(interval)
	if err != nil || parsed < 5*time.Minute || parsed > 60*time.Minute {
		return fmt.Errorf("RefreshInterval must be a duration between 5m and 60m, got %q", interval)
	}
	d.refreshInterval = parsed
	d.records = make(map[keyArray]discoveryRecord)
	d.connections = make(map[keyArray]int)
	// Copy the slice so callers cannot modify the running configuration.
	c.config.discovery.Services = append([]config.DiscoveryService(nil), c.config.discovery.Services...)
	if err := validateDiscoveryServices(c.config.discovery.Services, c.public); err != nil {
		return err
	}
	if len(c.config.discovery.Services) != 0 {
		_, err = d.announce(time.Now())
	}
	return err
}

func (d *serviceDiscovery) announce(now time.Time) (discoveryRecord, error) {
	p := discoveryPayload{Version: 1, Key: d.core.public, Issued: now.Unix(), Services: d.core.config.discovery.Services}
	payload, err := json.Marshal(p)
	if err != nil {
		return discoveryRecord{}, err
	}
	wire, err := json.Marshal(discoveryAnnouncement{payload, ed25519.Sign(d.core.secret, append([]byte(discoveryDomain), payload...))})
	if err != nil {
		return discoveryRecord{}, err
	}
	if len(wire) > discoveryMaxPacket {
		return discoveryRecord{}, fmt.Errorf("announcement exceeds %d bytes", discoveryMaxPacket)
	}
	return discoveryRecord{payload: p, wire: wire}, nil
}

func (d *serviceDiscovery) peers() map[keyArray]struct{} {
	d.mu.Lock()
	defer d.mu.Unlock()
	peers := make(map[keyArray]struct{})
	for key := range d.connections {
		peers[key] = struct{}{}
	}
	return peers
}

// Track authenticated links directly. The debug peer API also reads routing
// diagnostics, which are unnecessary for discovery and may change concurrently.
func (d *serviceDiscovery) connected(key keyArray) func() {
	d.mu.Lock()
	d.connections[key]++
	d.mu.Unlock()
	return func() {
		d.mu.Lock()
		defer d.mu.Unlock()
		d.connections[key]--
		if d.connections[key] == 0 {
			delete(d.connections, key)
		}
	}
}

func (d *serviceDiscovery) send(to keyArray, wire []byte) {
	bs := append([]byte{typeSessionProto, typeProtoDiscovery}, wire...)
	_, _ = d.core.PacketConn.WriteTo(bs, iwt.Addr(to[:]))
}

func (d *serviceDiscovery) cleanup(now time.Time) {
	for key, r := range d.records {
		if now.Unix() >= r.payload.Issued+int64(discoveryLifetime/time.Second) {
			delete(d.records, key)
		}
	}
}

func (d *serviceDiscovery) run() {
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	known := make(map[keyArray]int)
	var refreshed time.Time
	ownKey := keyArray(d.core.public)
	for {
		now := time.Now()
		peers := d.peers()
		publish := len(d.core.config.discovery.Services) > 0
		refresh := publish && now.Sub(refreshed) >= d.refreshInterval
		d.mu.Lock()
		d.cleanup(now)
		if refresh {
			r, _ := d.announce(now) // Configuration and packet size were checked at startup.
			d.records[ownKey] = r
			refreshed = now
		}
		own := d.records[ownKey]
		d.mu.Unlock()
		// Foreign snapshots are relayed only once, on acceptance in handle().
		// Periodic refresh and connection retries advertise only our own snapshot.
		for peer := range peers {
			if publish && (known[peer] < 3 || refresh) {
				d.send(peer, own.wire)
			}
		}

		for peer := range known {
			if _, ok := peers[peer]; !ok {
				delete(known, peer)
			}
		}
		for peer := range peers {
			if known[peer] < 3 {
				known[peer]++
			}
		}
		delay := 5 * time.Second
		if publish {
			delay = min(delay, time.Until(refreshed.Add(d.refreshInterval)))
		}
		timer.Reset(delay)
		select {
		case <-d.core.ctx.Done():
			return
		case <-timer.C:
		}
	}
}

func (d *serviceDiscovery) handle(from keyArray, wire []byte) {
	if !d.core.config.discovery.Enabled || len(wire) > discoveryMaxPacket {
		return
	}
	if _, ok := d.peers()[from]; !ok {
		return
	}
	var a discoveryAnnouncement
	var p discoveryPayload
	if json.Unmarshal(wire, &a) != nil || json.Unmarshal(a.Payload, &p) != nil {
		return
	}
	now := time.Now()
	if p.Version != 1 || len(p.Key) != ed25519.PublicKeySize || p.Issued > now.Unix()+30 || p.Issued <= now.Unix()-int64(discoveryLifetime/time.Second) {
		return
	}
	origin := keyArray(p.Key)
	if origin == keyArray(d.core.public) || validateDiscoveryServices(p.Services, p.Key) != nil {
		return
	}
	if !ed25519.Verify(p.Key, append([]byte(discoveryDomain), a.Payload...), a.Signature) {
		return
	}
	d.mu.Lock()
	d.cleanup(now)
	old, exists := d.records[origin]
	if (exists && old.payload.Issued >= p.Issued) || (!exists && len(d.records) >= discoveryMaxOrigins) {
		d.mu.Unlock()
		return
	}
	// A periodic renewal preserves the service list; only signed metadata
	// changes. A changed snapshot still replaces the services.
	if exists && slices.Equal(old.payload.Services, p.Services) {
		p.Services = old.payload.Services
	}
	d.records[origin] = discoveryRecord{payload: p, wire: append([]byte(nil), wire...)}
	d.mu.Unlock()
	if d.core.config.discovery.Forward {
		for peer := range d.peers() {
			if peer != from && peer != origin {
				d.send(peer, wire)
			}
		}
	}
}

// GetServices returns unexpired announcements, scoped by the publisher's key.
func (c *Core) GetServices() GetServicesResponse {
	result := GetServicesResponse{Services: []DiscoveredService{}}
	if !c.config.discovery.Enabled {
		return result
	}
	c.discovery.mu.Lock()
	defer c.discovery.mu.Unlock()
	c.discovery.cleanup(time.Now())
	for key, r := range c.discovery.records {
		for _, s := range r.payload.Services {
			result.Services = append(result.Services, DiscoveredService{s, hex.EncodeToString(key[:]), time.Unix(r.payload.Issued, 0).Add(discoveryLifetime)})
		}
	}
	sort.Slice(result.Services, func(i, j int) bool {
		a, b := result.Services[i], result.Services[j]
		if a.PublicKey != b.PublicKey {
			return a.PublicKey < b.PublicKey
		}
		return a.Name < b.Name
	})
	return result
}
