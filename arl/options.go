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
	"net/netip"
	"time"
)

const (
	// defaultMaxSize is applied when a caller passes a maxSize of 0, so that
	// a fetch is never unbounded.
	defaultMaxSize = uint64(256 * 1024 * 1024)

	// defaultHTTPTimeout bounds a whole http(s) fetch (connect, headers and
	// body).
	defaultHTTPTimeout = 10 * time.Minute

	// defaultGCSTimeout bounds a whole gcs fetch (listing and downloads).
	defaultGCSTimeout = 30 * time.Minute

	// maxListedObjects bounds how many objects a single gcs prefix may
	// expand to.
	maxListedObjects = 100000

	// maxConcurrentLimit bounds the number of concurrent fetch workers
	// a single ARL may spawn, however large a caller passes.
	maxConcurrentLimit = 1024
)

type options struct {
	// timeout overrides the per-method default when non-zero.
	timeout time.Duration
	// allowPrivateNetworks disables the destination guard of the default
	// http client.
	allowPrivateNetworks bool
	// allowedNetworks are destinations exempted from the guard.
	allowedNetworks []netip.Prefix
}

// Option customizes the behavior of an ARL. Options are optional, existing
// callers of NewARL and NewARLWithClient keep working unchanged.
type Option func(*options)

// WithTimeout overrides the default overall timeout of a fetch.
func WithTimeout(d time.Duration) Option {
	return func(o *options) {
		o.timeout = d
	}
}

// WithAllowPrivateNetworks lets http(s) fetches reach loopback, link-local,
// private, CGNAT and other non-public destinations. By default these are
// refused when connecting, which also covers redirects and DNS answers. Only
// use this for callers where the ARL is fully trusted.
func WithAllowPrivateNetworks() Option {
	return func(o *options) {
		o.allowPrivateNetworks = true
	}
}

// WithAllowedNetworks exempts specific destination networks from the
// non-public destination guard, for trusted internal callers that need to
// reach a specific internal service.
func WithAllowedNetworks(prefixes ...netip.Prefix) Option {
	return func(o *options) {
		o.allowedNetworks = append(o.allowedNetworks, prefixes...)
	}
}

func (o options) timeoutOr(def time.Duration) time.Duration {
	if o.timeout > 0 {
		return o.timeout
	}
	return def
}
