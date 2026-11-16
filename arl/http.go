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
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

func (a AuthenticatedResourceLocator) getHTTP() (chan Content, error) {
	fullURL := ""
	if a.methodName == "http" {
		fullURL = fmt.Sprintf("http://%s", a.methodDest)
	} else if a.methodName == "https" {
		fullURL = fmt.Sprintf("https://%s", a.methodDest)
	} else {
		return nil, ErrorMethodNotImplemented
	}

	// The context bounds the whole transfer, including the body, and the
	// archive expansion of a single object shares the same budget.
	deadline := time.Now().Add(a.opts.timeoutOr(defaultHTTPTimeout))
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", fullURL, nil)
	if err != nil {
		return nil, err
	}

	if a.authType == "basic" {
		components := strings.Split(a.authData, ":")
		if len(components) != 2 {
			return nil, errors.New("invalid basic authentication data")
		}
		req.SetBasicAuth(components[0], components[1])
	} else if a.authType == "bearer" {
		req.Header.Add("Authorization", fmt.Sprintf("bearer %s", a.authData))
	} else if a.authType == "token" {
		req.Header.Add("Authorization", fmt.Sprintf("token %s", a.authData))
	} else if a.authType == "otx" {
		req.Header.Add("X-OTX-API-KEY", a.authData)
	}

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("failed to get url: %s", resp.Status)
	}

	if resp.ContentLength > 0 && uint64(resp.ContentLength) > a.maxSize {
		return nil, ErrorResourceTooLarge
	}
	b, err := readLimited(resp.Body, a.maxSize)
	if err != nil {
		return nil, err
	}

	bodyContent := Content{
		FilePath: fullURL,
		Data:     b,
	}

	return multiplexContent(bodyContent, a.maxSize, deadline), nil
}

// readLimited reads at most max bytes, and fails if there is more.
func readLimited(r io.Reader, max uint64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, int64(max)+1))
	if err != nil {
		return nil, err
	}
	if uint64(len(b)) > max {
		return nil, ErrorResourceTooLarge
	}
	return b, nil
}
