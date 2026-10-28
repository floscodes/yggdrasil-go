package config

import (
	"bytes"
	"testing"
)

// ReadFrom previously sliced conf[0:2] for the BOM check without
// guarding the length, so empty or single-byte configs piped via
// -useconf panicked with index out of range.
func TestConfigReadFromEmpty(t *testing.T) {
	for _, tc := range []struct {
		name string
		body []byte
	}{
		{name: "empty", body: nil},
		{name: "single byte", body: []byte{'{'}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("ReadFrom must not panic on short input, got: %v", r)
				}
			}()
			var cfg NodeConfig
			_, _ = cfg.ReadFrom(bytes.NewReader(tc.body))
		})
	}
}

func TestConfig_Keys(t *testing.T) {
	/*
		var nodeConfig NodeConfig
		nodeConfig.NewKeys()

		publicKey1, err := hex.DecodeString(nodeConfig.PublicKey)

		if err != nil {
			t.Fatal("can not decode generated public key")
		}

		if len(publicKey1) == 0 {
			t.Fatal("empty public key generated")
		}

		privateKey1, err := hex.DecodeString(nodeConfig.PrivateKey)

		if err != nil {
			t.Fatal("can not decode generated private key")
		}

		if len(privateKey1) == 0 {
			t.Fatal("empty private key generated")
		}

		nodeConfig.NewKeys()

		publicKey2, err := hex.DecodeString(nodeConfig.PublicKey)

		if err != nil {
			t.Fatal("can not decode generated public key")
		}

		if bytes.Equal(publicKey2, publicKey1) {
			t.Fatal("same public key generated")
		}

		privateKey2, err := hex.DecodeString(nodeConfig.PrivateKey)

		if err != nil {
			t.Fatal("can not decode generated private key")
		}

		if bytes.Equal(privateKey2, privateKey1) {
			t.Fatal("same private key generated")
		}
	*/
}

func TestDiscoveryConfig(t *testing.T) {
	cfg := GenerateConfig()
	if cfg.Discovery.RefreshInterval != DefaultDiscoveryRefreshInterval {
		t.Fatal("unexpected default refresh interval")
	}
	if !cfg.Discovery.Enabled || !cfg.Discovery.Forward || len(cfg.Discovery.Services) != 0 {
		t.Fatal("discovery and forwarding must default to enabled without published services")
	}
	if err := cfg.UnmarshalHJSON([]byte(`{Discovery: {Enabled: true, Forward: true, RefreshInterval: "30m", Services: [{Name: "wiki", Address: "300::1", Port: 80, Protocol: "tcp"}]}}`)); err != nil {
		t.Fatal(err)
	}
	d := cfg.Discovery
	if !d.Enabled || !d.Forward || len(d.Services) != 1 || d.Services[0].Name != "wiki" || d.Services[0].Port != 80 || d.Services[0].Protocol != DiscoveryProtocolTCP || d.RefreshInterval != "30m" {
		t.Fatalf("unexpected discovery config: %+v", d)
	}
}

func TestDiscoveryDefaultOverrides(t *testing.T) {
	for _, tc := range []struct {
		body             string
		enabled, forward bool
	}{
		{`{}`, true, true},
		{`{Discovery: {Services: []}}`, true, true},
		{`{Discovery: {Enabled: false}}`, false, true},
		{`{Discovery: {Forward: false}}`, true, false},
		{`{Discovery: {Enabled: false, Forward: false}}`, false, false},
	} {
		t.Run(tc.body, func(t *testing.T) {
			var cfg NodeConfig
			if _, err := cfg.ReadFrom(bytes.NewBufferString(tc.body)); err != nil {
				t.Fatal(err)
			}
			if cfg.Discovery.Enabled != tc.enabled || cfg.Discovery.Forward != tc.forward || len(cfg.Discovery.Services) != 0 {
				t.Fatalf("unexpected discovery defaults/override: %+v", cfg.Discovery)
			}
		})
	}
}
