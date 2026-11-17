package core

import (
	"fmt"
	"time"

	"github.com/yggdrasil-network/yggdrasil-go/src/config"
)

const discoveryQueueSize = 64

// DiscoveryStatus reports local, lifetime counters; drops mean results may be incomplete.
// Counters and buckets are protected by serviceDiscovery.mu.
type DiscoveryStatus struct {
	Enabled              bool
	Capacity             int
	Publishers           int
	QueueDepth           int
	IngressDrops         uint64
	QueueDrops           uint64
	PublisherDrops       uint64
	EgressDrops          uint64
	CapacityDrops        uint64
	SendErrors           uint64
	VerificationAttempts uint64
	DuplicateDrops       uint64
}

type discoveryJob struct {
	from keyArray
	wire []byte
}

type discoveryPeerBudgets struct {
	ingress, egress discoveryBucket
}

type discoveryBucket struct {
	updated         time.Time
	messages, bytes float64
}

func (b *discoveryBucket) refill(now time.Time, limit config.DiscoveryRateLimit) {
	if b.updated.IsZero() {
		b.messages = float64(limit.BurstMessages)
		b.bytes = float64(limit.BurstBytes)
		b.updated = now
		return
	}
	if elapsed := now.Sub(b.updated).Minutes(); elapsed > 0 {
		b.messages = min(float64(limit.BurstMessages), b.messages+elapsed*float64(limit.MessagesPerMinute))
		b.bytes = min(float64(limit.BurstBytes), b.bytes+elapsed*float64(limit.BytesPerMinute))
		b.updated = now
	}
}

func (b *discoveryBucket) allow(now time.Time, size int, limit config.DiscoveryRateLimit) bool {
	b.refill(now, limit)
	if b.messages < 1 || b.bytes < float64(size) {
		return false
	}
	b.messages--
	b.bytes -= float64(size)
	return true
}

// Charge both buckets transactionally: a throttled peer cannot drain other peers' budget.
func discoveryAllow(now time.Time, size int, global *discoveryBucket, globalLimit config.DiscoveryRateLimit, peer *discoveryBucket, peerLimit config.DiscoveryRateLimit) bool {
	g, p := *global, *peer
	gok := g.allow(now, size, globalLimit)
	pok := p.allow(now, size, peerLimit)
	if !gok || !pok {
		return false
	}
	*global, *peer = g, p
	return true
}

func discoveryLimits(in config.DiscoveryRateLimits) (config.DiscoveryRateLimits, error) {
	// Provisional experimental defaults, not CPU capacity guarantees. Bytes include framing
	// for egress; ingress and publisher budgets count the complete JSON envelope.
	defaults := config.DiscoveryRateLimits{
		Ingress:     config.DiscoveryRateLimit{MessagesPerMinute: 7680, BytesPerMinute: 60 * 1024 * 1024, BurstMessages: 256, BurstBytes: 2 * 1024 * 1024},
		PeerIngress: config.DiscoveryRateLimit{MessagesPerMinute: 3840, BytesPerMinute: 30 * 1024 * 1024, BurstMessages: 128, BurstBytes: 1024 * 1024},
		Egress:      config.DiscoveryRateLimit{MessagesPerMinute: 7680, BytesPerMinute: 60 * 1024 * 1024, BurstMessages: 256, BurstBytes: 2 * 1024 * 1024},
		PeerEgress:  config.DiscoveryRateLimit{MessagesPerMinute: 1920, BytesPerMinute: 15 * 1024 * 1024, BurstMessages: 128, BurstBytes: 1024 * 1024},
		Publisher:   config.DiscoveryRateLimit{MessagesPerMinute: 1, BytesPerMinute: discoveryMaxPacket, BurstMessages: 3, BurstBytes: 3 * discoveryMaxPacket},
	}
	for _, pair := range []struct {
		name     string
		dst      *config.DiscoveryRateLimit
		fallback config.DiscoveryRateLimit
	}{
		{"Ingress", &in.Ingress, defaults.Ingress},
		{"PeerIngress", &in.PeerIngress, defaults.PeerIngress},
		{"Egress", &in.Egress, defaults.Egress},
		{"PeerEgress", &in.PeerEgress, defaults.PeerEgress},
		{"Publisher", &in.Publisher, defaults.Publisher},
	} {
		fields := []struct {
			dst      *int
			fallback int
		}{
			{&pair.dst.MessagesPerMinute, pair.fallback.MessagesPerMinute},
			{&pair.dst.BytesPerMinute, pair.fallback.BytesPerMinute},
			{&pair.dst.BurstMessages, pair.fallback.BurstMessages},
			{&pair.dst.BurstBytes, pair.fallback.BurstBytes},
		}
		for _, f := range fields {
			if *f.dst < 0 {
				return in, fmt.Errorf("discovery RateLimits.%s values must be positive or zero for defaults", pair.name)
			}
			if *f.dst == 0 {
				*f.dst = f.fallback
			}
		}
		if pair.dst.BurstBytes < discoveryMaxPacket+2 {
			return in, fmt.Errorf("discovery RateLimits.%s.BurstBytes must be at least %d", pair.name, discoveryMaxPacket+2)
		}
	}
	return in, nil
}

// admit runs before copying, decoding or verifying a body. No state is allocated for
// claimed publisher keys. Peer limiter state exists only for active authenticated links.
func (d *serviceDiscovery) admit(from keyArray, wire []byte) bool {
	if !d.core.config.discovery.Enabled {
		return false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	peer := d.peerBudgets[from]
	if peer == nil {
		return false
	}
	if !discoveryAllow(time.Now(), len(wire), &d.ingress, d.limits.Ingress, &peer.ingress, d.limits.PeerIngress) {
		d.stats.IngressDrops++
		return false
	}
	if len(wire) > discoveryMaxPacket {
		d.stats.IngressDrops++
		return false
	}
	return true
}

func (d *serviceDiscovery) enqueue(from keyArray, wire []byte) {
	if !d.admit(from, wire) {
		return
	}
	// Serialize producers so at most one extra bounded copy is made outside the queue.
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.queue) == cap(d.queue) {
		d.stats.QueueDrops++
		return
	}
	d.queue <- discoveryJob{from: from, wire: append([]byte(nil), wire...)}
}

func (d *serviceDiscovery) receive() {
	for {
		select {
		case <-d.core.ctx.Done():
			return
		case job := <-d.queue:
			d.process(job.from, job.wire)
		}
	}
}

func (c *Core) GetDiscoveryStatus() DiscoveryStatus {
	d := &c.discovery
	d.mu.Lock()
	defer d.mu.Unlock()
	d.cleanup(time.Now())
	status := d.stats
	status.Enabled = c.config.discovery.Enabled
	status.Capacity = discoveryMaxOrigins
	status.Publishers = len(d.records)
	status.QueueDepth = len(d.queue)
	return status
}
