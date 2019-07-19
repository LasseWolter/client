// config.go - Katzenpost client configuration.
// Copyright (C) 2018  Yawning Angel, David Stainton.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

// Package config implements the configuration for the Katzenpost client.
package config

import (
	"errors"
	"fmt"
	"github.com/BurntSushi/toml"
	nvClient "github.com/katzenpost/authority/nonvoting/client"
	vClient "github.com/katzenpost/authority/voting/client"
	vServerConfig "github.com/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/client/internal/proxy"
	"github.com/katzenpost/core/crypto/eddsa"
	"github.com/katzenpost/core/log"
	"github.com/katzenpost/core/pki"
	registration "github.com/katzenpost/registration_client"
	"golang.org/x/net/idna"
	"io/ioutil"
	"strings"
)

const (
	defaultLogLevel                    = "NOTICE"
	defaultPollingInterval             = 10
	defaultInitialMaxPKIRetrievalDelay = 10
	defaultSessionDialTimeout          = 10
	defaultMessageNum                  = 1
	defaultInterval                    = 5000
	defaultBlockSize                   = 1
)

var defaultLogging = Logging{
	Disable: false,
	File:    "",
	Level:   defaultLogLevel,
}

// Logging is the logging configuration.
type Logging struct {
	// Disable disables logging entirely.
	Disable bool

	// File specifies the log file, if omitted stdout will be used.
	File string

	// Level specifies the log level.
	Level string
}

func (lCfg *Logging) validate() error {
	lvl := strings.ToUpper(lCfg.Level)
	switch lvl {
	case "ERROR", "WARNING", "NOTICE", "INFO", "DEBUG":
	case "":
		lCfg.Level = defaultLogLevel
	default:
		return fmt.Errorf("config: Logging: Level '%v' is invalid", lCfg.Level)
	}
	lCfg.Level = lvl // Force uppercase.
	return nil
}

// Debug is the debug configuration.
type Debug struct {
	DisableDecoyLoops bool

	// SessionDialTimeout is the number of seconds that a session dial
	// is allowed to take until it is cancelled.
	SessionDialTimeout int

	// InitialMaxPKIRetrievalDelay is the initial maximum number of seconds
	// we are willing to wait for the retreival of the PKI document.
	InitialMaxPKIRetrievalDelay int

	// CaseSensitiveUserIdentifiers disables the forced lower casing of
	// the Account `User` field.
	CaseSensitiveUserIdentifiers bool

	// PollingInterval is the interval in seconds that will be used to
	// poll the receive queue.  By default this is 30 seconds.  Reducing
	// the value too far WILL result in uneccesary Provider load, and
	// increasing the value too far WILL adversely affect large message
	// transmit performance.
	PollingInterval int
}

func (d *Debug) fixup() {
	if d.PollingInterval == 0 {
		d.PollingInterval = defaultPollingInterval
	}
	if d.InitialMaxPKIRetrievalDelay == 0 {
		d.InitialMaxPKIRetrievalDelay = defaultInitialMaxPKIRetrievalDelay
	}
	if d.SessionDialTimeout == 0 {
		d.SessionDialTimeout = defaultSessionDialTimeout
	}
}

// NonvotingAuthority is a non-voting authority configuration.
type NonvotingAuthority struct {
	// Address is the IP address/port combination of the authority.
	Address string

	// PublicKey is the authority's public key.
	PublicKey *eddsa.PublicKey
}

// New constructs a pki.Client with the specified non-voting authority config.
func (nvACfg *NonvotingAuthority) New(l *log.Backend, pCfg *proxy.Config) (pki.Client, error) {
	cfg := &nvClient.Config{
		LogBackend:    l,
		Address:       nvACfg.Address,
		PublicKey:     nvACfg.PublicKey,
		DialContextFn: pCfg.ToDialContext("nonvoting:" + nvACfg.PublicKey.String()),
	}
	return nvClient.New(cfg)
}

func (nvACfg *NonvotingAuthority) validate() error {
	if nvACfg.PublicKey == nil {
		return fmt.Errorf("PublicKey is missing")
	}
	return nil
}

// VotingAuthority is a voting authority configuration.
type VotingAuthority struct {
	Peers []*vServerConfig.AuthorityPeer
}

// New constructs a pki.Client with the specified non-voting authority config.
func (vACfg *VotingAuthority) New(l *log.Backend, pCfg *proxy.Config) (pki.Client, error) {
	cfg := &vClient.Config{
		LogBackend:    l,
		Authorities:   vACfg.Peers,
		DialContextFn: pCfg.ToDialContext("voting"),
	}
	return vClient.New(cfg)
}

func (vACfg *VotingAuthority) validate() error {
	if vACfg.Peers == nil || len(vACfg.Peers) == 0 {
		return errors.New("VotingAuthority failure, must specify at least one peer.")
	}
	for _, peer := range vACfg.Peers {
		err := peer.Validate()
		if err != nil {
			return err
		}
	}
	return nil
}

// NewPKIClient returns a voting or nonvoting implementation of pki.Client or error
func (c *Config) NewPKIClient(l *log.Backend, pCfg *proxy.Config) (pki.Client, error) {
	switch {
	case c.NonvotingAuthority != nil:
		return c.NonvotingAuthority.New(l, pCfg)
	case c.VotingAuthority != nil:
		return c.VotingAuthority.New(l, pCfg)
	}
	return nil, fmt.Errorf("No Authority found")
}

// Panda is the PANDA configuration needed by clients
// in order to use the PANDA service
type Panda struct {
	// Receiver is the recipient ID that shall receive the Sphinx packets destined
	// for this PANDA service.
	Receiver string
	// Provider is the Provider on this mix network which is hosting this PANDA service.
	Provider string
	// BlobSize is the size of the PANDA blobs that clients will use.
	BlobSize int
}

func (p *Panda) validate() error {
	if p.Receiver == "" {
		return fmt.Errorf("Receiver is missing")
	}
	if p.Provider == "" {
		return fmt.Errorf("Provider is missing")
	}
	return nil
}

// Account is a provider account configuration.
type Account struct {
	// Provider is the provider identifier used by this account.
	Provider string

	// ProviderKeyPin is the optional pinned provider signing key.
	ProviderKeyPin *eddsa.PublicKey
}

func (accCfg *Account) fixup(cfg *Config) error {
	var err error
	accCfg.Provider, err = idna.Lookup.ToASCII(accCfg.Provider)
	return err
}

func (accCfg *Account) validate(cfg *Config) error {
	if accCfg.Provider == "" {
		return fmt.Errorf("Provider is missing")
	}
	return nil
}

// Registration is used for the client's Provider account registration.
type Registration struct {
	Address string
	Options *registration.Options
}

func (r *Registration) validate() error {
	if r.Address == "" {
		return errors.New("Registration Address cannot be empty.")
	}
	return nil
}

// UpstreamProxy is the outgoing connection proxy configuration.
type UpstreamProxy struct {
	// Type is the proxy type (Eg: "none"," socks5").
	Type string

	// Network is the proxy address' network (`unix`, `tcp`).
	Network string

	// Address is the proxy's address.
	Address string

	// User is the optional proxy username.
	User string

	// Password is the optional proxy password.
	Password string
}

func (uCfg *UpstreamProxy) toProxyConfig() (*proxy.Config, error) {
	// This is kind of dumb, but this is the cleanest way I can think of
	// doing this.
	cfg := &proxy.Config{
		Type:     uCfg.Type,
		Network:  uCfg.Network,
		Address:  uCfg.Address,
		User:     uCfg.User,
		Password: uCfg.Password,
	}
	if err := cfg.FixupAndValidate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// The experiment struct contains parameters that determine different parts of the experiment
type Experiment struct {
	// Number of messages
	MessageNum int

	// Time that the experiment should run [in minutes] - setting this value will make MessageNum useless
	// as messages will be send as long as the message lasts
	Duration int

	// Size of message blocks - how many messages should be sent at once?
	BlockSize int

	// Interval - time interval between two message blocks [in milliseconds]
	Interval int
}

// Applies the default values for experiment parameters if necessary
func (exp *Experiment) applyDefaults() {
	if exp.MessageNum <= 0 {
		exp.MessageNum = defaultMessageNum
	}
	if exp.BlockSize <= 0 {
		exp.BlockSize = defaultBlockSize
	}
	if exp.Interval <= 0 {
		exp.Interval = defaultInterval
	}
}

// Config is the top level client configuration.
type Config struct {
	Logging            *Logging
	UpstreamProxy      *UpstreamProxy
	Debug              *Debug
	NonvotingAuthority *NonvotingAuthority
	VotingAuthority    *VotingAuthority
	Account            *Account
	Registration       *Registration
	Panda              *Panda
	upstreamProxy      *proxy.Config
	Experiment         *Experiment
}

// UpstreamProxyConfig returns the configured upstream proxy, suitable for
// internal use.  Most people should not use this.
func (c *Config) UpstreamProxyConfig() *proxy.Config {
	return c.upstreamProxy
}

// FixupAndValidate applies defaults to config entries and validates the
// supplied configuration.  Most people should call one of the Load variants
// instead.
func (c *Config) FixupAndValidate() error {
	// Handle missing sections if possible.
	if c.Logging == nil {
		c.Logging = &defaultLogging
	}
	if c.Debug == nil {
		c.Debug = &Debug{
			PollingInterval:             defaultPollingInterval,
			InitialMaxPKIRetrievalDelay: defaultInitialMaxPKIRetrievalDelay,
		}
	} else {
		c.Debug.fixup()
	}
	// Apply default values for experiment if necessary
	c.Experiment.applyDefaults()

	// Validate/fixup the various sections.
	if err := c.Logging.validate(); err != nil {
		return err
	}
	if uCfg, err := c.UpstreamProxy.toProxyConfig(); err == nil {
		c.upstreamProxy = uCfg
	} else {
		return err
	}
	switch {
	case c.NonvotingAuthority == nil && c.VotingAuthority != nil:
		if err := c.VotingAuthority.validate(); err != nil {
			return fmt.Errorf("config: NonvotingAuthority is invalid: %s", err)
		}
	case c.NonvotingAuthority != nil && c.VotingAuthority == nil:
		if err := c.NonvotingAuthority.validate(); err != nil {
			return fmt.Errorf("config: NonvotingAuthority is invalid: %s", err)
		}
	default:
		return fmt.Errorf("config: Authority configuration is invalid")
	}

	// Account
	if err := c.Account.fixup(c); err != nil {
		return fmt.Errorf("config: Account is invalid: %v", err)
	}
	if err := c.Account.validate(c); err != nil {
		return fmt.Errorf("config: Account is invalid: %v", err)
	}

	// Panda is optional
	if c.Panda != nil {
		err := c.Panda.validate()
		if err != nil {
			return fmt.Errorf("config: Panda config is invalid: %v", err)
		}
	}

	// Registration
	if c.Registration == nil {
		return errors.New("config: error, Registration config section is non-optional")
	} else {
		err := c.Registration.validate()
		if err != nil {
			return err
		}
	}
	return nil
}

// Load parses and validates the provided buffer b as a config file body and
// returns the Config.
func Load(b []byte) (*Config, error) {
	cfg := new(Config)
	md, err := toml.Decode(string(b), cfg)
	if err != nil {
		return nil, err
	}
	if undecoded := md.Undecoded(); len(undecoded) != 0 {
		return nil, fmt.Errorf("config: Undecoded keys in config file: %v", undecoded)
	}
	if err := cfg.FixupAndValidate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// LoadFile loads, parses, and validates the provided file and returns the
// Config.
func LoadFile(f string) (*Config, error) {
	b, err := ioutil.ReadFile(f)
	if err != nil {
		return nil, err
	}
	return Load(b)
}
