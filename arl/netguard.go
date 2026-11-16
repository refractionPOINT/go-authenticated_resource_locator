// *************************************************************************
//
// REFRACTION POINT CONFIDENTIAL
// __________________
//
//	Copyright 2018 Refraction Point Inc.
//	All Rights Reserved.
//
// NOTICE:  All information contained herein is, and remains
// the property of Refraction Point Inc. and its suppliers,
// if any.  The intellectual and technical concepts contained
// herein are proprietary to Refraction Point Inc
// and its suppliers and may be covered by U.S. and Foreign Patents,
// patents in process, and are protected by trade secret or copyright law.
// Dissemination of this information or reproduction of this material
// is strictly forbidden unless prior written permission is obtained
// from Refraction Point Inc.
package arl

import (
	"net"
	"net/http"
	"net/netip"
	"sync"
	"syscall"
	"time"
)

var blockedPrefixes = mustPrefixes(
	"0.0.0.0/8",       // "this" network
	"100.64.0.0/10",   // CGNAT
	"192.0.0.0/24",    // IETF protocol assignments
	"192.0.2.0/24",    // documentation
	"198.18.0.0/15",   // benchmarking
	"198.51.100.0/24", // documentation
	"203.0.113.0/24",  // documentation
	"240.0.0.0/4",     // reserved + broadcast
	"::/96",           // unspecified, IPv4-compatible
	"::ffff:0:0:0/96", // SIIT translated
	"64:ff9b:1::/48",  // local-use NAT64
	"100::/64",        // discard-only
	"2001::/32",       // Teredo
	"2001:db8::/32",   // documentation
	"fec0::/10",       // deprecated site-local
)

var (
	nat64Prefix     = netip.MustParsePrefix("64:ff9b::/96")
	sixToFourPrefix = netip.MustParsePrefix("2002::/16")
)

func mustPrefixes(s ...string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(s))
	for _, p := range s {
		out = append(out, netip.MustParsePrefix(p))
	}
	return out
}

// isBlockedAddr reports whether a destination is not a public unicast address.
func isBlockedAddr(a netip.Addr) bool {
	a = a.WithZone("").Unmap()
	if !a.IsValid() {
		return true
	}
	if a.IsLoopback() || a.IsPrivate() || a.IsUnspecified() ||
		a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() ||
		a.IsInterfaceLocalMulticast() || a.IsMulticast() {
		return true
	}
	for _, p := range blockedPrefixes {
		if p.Contains(a) {
			return true
		}
	}
	// NAT64 and 6to4 embed an IPv4 address, apply the same rules to it.
	b := a.As16()
	if nat64Prefix.Contains(a) {
		return isBlockedAddr(netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]}))
	}
	if sixToFourPrefix.Contains(a) {
		return isBlockedAddr(netip.AddrFrom4([4]byte{b[2], b[3], b[4], b[5]}))
	}
	return false
}

// guardControl is a net.Dialer Control function: it runs on every connection
// attempt with the already resolved address, so it covers redirects, DNS
// answers changing between lookups and literal IPs alike.
func guardControl(allowed []netip.Prefix) func(network, address string, c syscall.RawConn) error {
	return func(network, address string, _ syscall.RawConn) error {
		ap, err := netip.ParseAddrPort(address)
		if err != nil {
			return ErrorDestinationNotAllowed
		}
		addr := ap.Addr().WithZone("").Unmap()
		for _, p := range allowed {
			if p.Contains(addr) {
				return nil
			}
		}
		if isBlockedAddr(addr) {
			return ErrorDestinationNotAllowed
		}
		return nil
	}
}

func newTransport(o options) *http.Transport {
	dialer := &net.Dialer{
		Timeout:   15 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	if !o.allowPrivateNetworks {
		dialer.Control = guardControl(o.allowedNetworks)
	}
	return &http.Transport{
		// No environment proxy: the destination guard is enforced on the
		// connection and a proxy would hide the real destination.
		Proxy:                 nil,
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		TLSHandshakeTimeout:   15 * time.Second,
		ResponseHeaderTimeout: 60 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		IdleConnTimeout:       60 * time.Second,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   4,
	}
}

// checkRedirect refuses scheme downgrades and does not forward the API key
// header to another host (net/http only drops Authorization by itself).
func checkRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 10 {
		return errTooManyRedirects
	}
	prev := via[len(via)-1]
	if prev.URL.Scheme == "https" && req.URL.Scheme != "https" {
		return ErrorInsecureRedirect
	}
	if prev.URL.Host != req.URL.Host {
		req.Header.Del("X-OTX-API-KEY")
	}
	return nil
}

var (
	sharedClientsMu sync.Mutex
	sharedClients   = map[bool]*http.Client{}
)

// newHTTPClient returns the default client: no total timeout (callers use
// request contexts), destination guard unless disabled.
func newHTTPClient(o options) *http.Client {
	if len(o.allowedNetworks) > 0 {
		// Rare, per-ARL configuration: not worth sharing.
		return &http.Client{Transport: newTransport(o), CheckRedirect: checkRedirect}
	}
	sharedClientsMu.Lock()
	defer sharedClientsMu.Unlock()
	c, ok := sharedClients[o.allowPrivateNetworks]
	if !ok {
		c = &http.Client{Transport: newTransport(o), CheckRedirect: checkRedirect}
		sharedClients[o.allowPrivateNetworks] = c
	}
	return c
}
