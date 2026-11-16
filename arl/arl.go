// *************************************************************************
//
// REFRACTION POINT CONFIDENTIAL
// __________________
//
//  Copyright 2018 Refraction Point Inc.
//  All Rights Reserved.
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
//

package arl

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"strings"
	"time"
)

type AuthenticatedResourceLocator struct {
	arl           string
	maxSize       uint64
	maxConcurrent uint64

	methodName string
	methodDest string
	authType   string
	authData   string

	httpClient *http.Client
	opts       options

	get func() (chan Content, error)
}

type Content struct {
	FilePath string
	Data     []byte
	Error    error
}

var ErrorMethodNotImplemented = errors.New("method not implemented")
var ErrorAuthNotImplemented = errors.New("auth not implemented")
var ErrorInvalidFormat = errors.New("invalid ARL format")
var ErrorResourceNotFound = errors.New("resource not found")
var ErrorResourceTooLarge = errors.New("maximum resource size exceeded")
var ErrorInvalidCredentials = errors.New("invalid credentials")
var ErrorDestinationNotAllowed = errors.New("destination address is not allowed")
var ErrorInsecureRedirect = errors.New("redirect from https to http refused")
var errTooManyRedirects = errors.New("stopped after 10 redirects")

var supportedMethods = map[string]map[string]bool{
	"http": {
		"basic":  true,
		"bearer": true,
		"token":  true,
		"otx":    true,
		"":       true,
	},
	"https": {
		"basic":  true,
		"bearer": true,
		"token":  true,
		"otx":    true,
		"":       true,
	},
	"gcs": {
		"gaia": true,
	},
	"github": {
		"token": true,
		"ssh":   true,
		"":      true,
	},
}

// NewARLWithClient is like NewARL but uses the given http client for the http
// and https methods (nil selects the default client). A custom client is used
// as-is: the non-public destination guard and transport timeouts described on
// NewARL only apply to the default client, it is up to the caller to provide
// equivalent protections in a custom one.
func NewARLWithClient(arl string, maxSize uint64, maxConcurrent uint64, client *http.Client, opts ...Option) (AuthenticatedResourceLocator, error) {
	if maxSize == 0 {
		maxSize = defaultMaxSize
	}
	// Keep size arithmetic within int64.
	maxSize = min(maxSize, math.MaxInt64/2)
	if maxConcurrent == 0 {
		maxConcurrent = 1
	}
	// Keep a pathological value from spawning an unbounded number of
	// concurrent fetch workers.
	maxConcurrent = min(maxConcurrent, maxConcurrentLimit)
	a := AuthenticatedResourceLocator{
		arl:           arl,
		maxSize:       maxSize,
		maxConcurrent: maxConcurrent,
		httpClient:    client,
	}
	for _, o := range opts {
		o(&a.opts)
	}
	if a.httpClient == nil {
		a.httpClient = newHTTPClient(a.opts)
	}

	if strings.HasPrefix(arl, "https://") {
		// This is a shortcut for backwards compatibility.
		a.methodName = "https"
		a.methodDest = arl[len("https://"):]
	} else if strings.HasPrefix(arl, "[") && strings.HasSuffix(arl, "]") {
		// Remove prefix and suffix.
		arl = arl[1 : len(arl)-1]
		// Split the ARL into its components.
		components := strings.Split(arl, ",")
		if len(components) != 4 && len(components) != 2 {
			return a, ErrorInvalidFormat
		}
		// Remove any unneeded spaces.
		for i := range components {
			components[i] = strings.TrimSpace(components[i])
		}
		// Load the components in order.
		a.methodName = strings.ToLower(components[0])
		a.methodDest = components[1]
		if len(components) == 4 {
			a.authType = strings.ToLower(components[2])
			a.authData = components[3]
		}
	} else {
		return a, ErrorInvalidFormat
	}

	// Validate the method is supported.
	if _, ok := supportedMethods[a.methodName]; !ok {
		return a, ErrorMethodNotImplemented
	}
	// Validate the method supports the auth.
	if _, ok := supportedMethods[a.methodName][a.authType]; !ok {
		return a, ErrorAuthNotImplemented
	}

	// Resolve the relevant callback for this method.
	a.get = map[string]func() (chan Content, error){
		"http":   a.getHTTP,
		"https":  a.getHTTP,
		"gcs":    a.getGCS,
		"github": a.getGitHub,
	}[a.methodName]

	return a, nil
}

// NewARL parses an ARL. maxSize bounds the total number of bytes fetched (and
// expanded, for archives) by every method, 0 selects a generous default.
//
// By default http(s) fetches use a client with timeouts that refuses to
// connect to non-public destinations (loopback, link-local including cloud
// metadata, private, CGNAT, ...) at connection time, so redirects and DNS
// answers are covered too. See WithAllowPrivateNetworks for trusted callers.
// The gcs method only accepts Google service account keys.
func NewARL(arl string, maxSize uint64, maxConcurrent uint64, opts ...Option) (AuthenticatedResourceLocator, error) {
	return NewARLWithClient(arl, maxSize, maxConcurrent, nil, opts...)
}

func (a *AuthenticatedResourceLocator) Fetch() (chan Content, error) {
	return a.get()
}

// abandonGrace is how long a final (error) message waits for a consumer once
// a fetch has run out of time; past that the consumer is considered gone.
var abandonGrace = 10 * time.Second

// deliverFinal hands the last message of a fetch to the consumer. Unlike the
// regular sends it does not depend on the fetch deadline, which may already
// have passed, so a failed or incomplete fetch is never mistaken for a
// complete one. It only gives up on a consumer that has stopped reading.
func deliverFinal(out chan<- Content, c Content) {
	t := time.NewTimer(abandonGrace)
	defer t.Stop()
	select {
	case out <- c:
	case <-t.C:
	}
}

func incompleteError(ctx context.Context) error {
	return fmt.Errorf("fetch incomplete: %w", ctx.Err())
}

// multiplexContent expands tar and zip content into its files. The total
// expanded size is bounded by maxExpanded, and an abandoned consumer can
// hold the expansion for at most the remaining time until deadline (plus
// the grace period of the final message).
func multiplexContent(c Content, maxExpanded uint64, deadline time.Time) chan Content {
	out := make(chan Content, 1)

	go func() {
		defer close(out)
		expandArchive(out, c, maxExpanded, deadline)
	}()

	return out
}

// expandArchive does the work of multiplexContent, returning once everything
// was sent, the consumer was given up on, or the budget ran out.
func expandArchive(out chan Content, c Content, maxExpanded uint64, deadline time.Time) {
	{
		ctx, cancel := context.WithDeadline(context.Background(), deadline)
		defer cancel()
		// send gives up when the deadline passes so an abandoned
		// consumer cannot pin the expansion forever. The non-blocking
		// attempt first: a consumer that is actively reading gets the
		// last entries even once the deadline has passed, expiry only
		// decides when sends would block.
		send := func(c Content) bool {
			select {
			case out <- c:
				return true
			default:
			}
			select {
			case out <- c:
				return true
			case <-ctx.Done():
				return false
			}
		}

		remaining := maxExpanded
		// take reads one entry within the remaining budget.
		take := func(r io.Reader) ([]byte, error) {
			b := bytes.Buffer{}
			n, err := io.Copy(&b, io.LimitReader(r, int64(remaining)+1))
			if err == nil && uint64(n) > remaining {
				err = ErrorResourceTooLarge
			}
			if uint64(n) >= remaining {
				remaining = 0
			} else {
				remaining -= uint64(n)
			}
			return b.Bytes(), err
		}

		tarReader := tar.NewReader(bytes.NewReader(c.Data))
		for {
			header, err := tarReader.Next()
			if err == io.EOF {
				return
			}
			if err != nil {
				break
			}
			// We only care about regular files.
			if header.Typeflag != tar.TypeReg {
				continue
			}
			data, err := take(tarReader)
			if !send(Content{
				FilePath: fmt.Sprintf("/%s", header.Name),
				Data:     data,
				Error:    err,
			}) {
				deliverFinal(out, Content{Error: incompleteError(ctx)})
				return
			}
			if errors.Is(err, ErrorResourceTooLarge) {
				return
			}
		}

		zipReader, err := zip.NewReader(bytes.NewReader(c.Data), int64(len(c.Data)))
		if err != nil {
			// So this was not a tar and not a zip, we'll just return
			// the file as-is.
			if !send(c) {
				deliverFinal(out, Content{Error: incompleteError(ctx)})
			}
			return
		}
		for _, zipFile := range zipReader.File {
			newFile := Content{
				FilePath: fmt.Sprintf("/%s", zipFile.Name),
			}
			f, err := zipFile.Open()
			if err != nil {
				newFile.Error = err
			} else {
				newFile.Data, err = take(f)
				f.Close()
				newFile.Error = err
			}
			if !send(newFile) {
				deliverFinal(out, Content{Error: incompleteError(ctx)})
				return
			}
			if errors.Is(newFile.Error, ErrorResourceTooLarge) {
				return
			}
		}
	}
}
