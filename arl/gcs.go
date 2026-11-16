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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"

	"cloud.google.com/go/storage"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
)

// Token endpoints Google service account keys point to.
var allowedTokenURIs = map[string]bool{
	"https://oauth2.googleapis.com/token":        true,
	"https://accounts.google.com/o/oauth2/token": true,
}

// serviceAccountKey holds the only fields of a service account key that are
// ever used.
type serviceAccountKey struct {
	Type         string `json:"type"`
	ProjectID    string `json:"project_id,omitempty"`
	PrivateKeyID string `json:"private_key_id,omitempty"`
	PrivateKey   string `json:"private_key"`
	ClientEmail  string `json:"client_email"`
	ClientID     string `json:"client_id,omitempty"`
	TokenURI     string `json:"token_uri,omitempty"`
}

// sanitizeServiceAccountKey checks that the JSON is a Google service account
// key using Google's own token endpoint and returns a copy that only holds the
// fields needed to sign in. Any other credential type, token endpoint or
// universe domain is refused, no file or network access happens here.
func sanitizeServiceAccountKey(blob []byte) ([]byte, error) {
	var k serviceAccountKey
	var extra struct {
		UniverseDomain string `json:"universe_domain"`
	}
	if err := json.Unmarshal(blob, &k); err != nil {
		return nil, fmt.Errorf("%w: not a valid service account key", ErrorInvalidCredentials)
	}
	if err := json.Unmarshal(blob, &extra); err != nil {
		return nil, fmt.Errorf("%w: not a valid service account key", ErrorInvalidCredentials)
	}
	if k.Type != "service_account" {
		return nil, fmt.Errorf("%w: only service_account keys are supported", ErrorInvalidCredentials)
	}
	if k.PrivateKey == "" || k.ClientEmail == "" {
		return nil, fmt.Errorf("%w: service account key is missing private_key or client_email", ErrorInvalidCredentials)
	}
	if k.TokenURI != "" && !allowedTokenURIs[k.TokenURI] {
		return nil, fmt.Errorf("%w: unsupported token_uri", ErrorInvalidCredentials)
	}
	if extra.UniverseDomain != "" && extra.UniverseDomain != "googleapis.com" {
		return nil, fmt.Errorf("%w: unsupported universe_domain", ErrorInvalidCredentials)
	}
	return json.Marshal(k)
}

func (a AuthenticatedResourceLocator) getGCS() (chan Content, error) {
	authBlob, err := base64.StdEncoding.DecodeString(a.authData)
	if err != nil {
		return nil, err
	}
	keyJSON, err := sanitizeServiceAccountKey(authBlob)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), a.opts.timeoutOr(defaultGCSTimeout))
	client, err := storage.NewClient(ctx,
		option.WithAuthCredentialsJSON(option.ServiceAccount, keyJSON),
		option.WithScopes(storage.ScopeReadOnly),
	)
	if err != nil {
		cancel()
		return nil, err
	}

	components := strings.Split(a.methodDest, "/")
	bucketName := components[0]
	bucketPath := ""
	if len(components) == 1 {
		bucketPath = ""
	} else {
		bucketPath = strings.Join(components[1:], "/")
	}

	bucket := client.Bucket(bucketName)

	it := bucket.Objects(ctx, &storage.Query{Prefix: bucketPath})
	blobs := []*storage.ObjectAttrs{}
	listedSize := uint64(0)
	for {
		attrs, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			client.Close()
			cancel()
			return nil, fmt.Errorf("failed to list gcs objects: %w", err)
		}
		listedSize += uint64(max(attrs.Size, 0))
		if listedSize > a.maxSize || len(blobs) >= maxListedObjects {
			client.Close()
			cancel()
			return nil, ErrorResourceTooLarge
		}
		blobs = append(blobs, attrs)
	}

	chOut := make(chan Content)
	chIn := make(chan *storage.ObjectAttrs)
	wg := sync.WaitGroup{}
	downloaded := atomic.Uint64{}

	// send gives up when the deadline passes so an abandoned consumer
	// cannot pin the workers forever.
	send := func(c Content) bool {
		select {
		case chOut <- c:
			return true
		case <-ctx.Done():
			return false
		}
	}

	fetchOne := func(o *storage.ObjectAttrs) Content {
		out := Content{
			FilePath: fmt.Sprintf("gcs://%s/%s", bucketName, o.Name),
		}
		reader, err := bucket.Object(o.Name).NewReader(ctx)
		if err != nil {
			out.Error = err
			return out
		}
		defer reader.Close()
		out.Data, out.Error = readLimited(reader, a.maxSize)
		if out.Error == nil && downloaded.Add(uint64(len(out.Data))) > a.maxSize {
			out.Data = nil
			out.Error = ErrorResourceTooLarge
		}
		return out
	}

	for i := uint64(0); i < a.maxConcurrent; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for o := range chIn {
				out := fetchOne(o)
				// If there was only one blob, we check if
				// it's an archive and multiplex it.
				if len(blobs) == 1 && out.Error == nil {
					parts := multiplexContent(out, a.maxSize, a.opts.timeoutOr(defaultGCSTimeout))
					for b := range parts {
						if !send(b) {
							go func() {
								for range parts {
								}
							}()
							return
						}
					}
					continue
				}
				if !send(out) {
					return
				}
			}
		}()
	}

	go func() {
		defer close(chIn)
		for _, b := range blobs {
			select {
			case chIn <- b:
			case <-ctx.Done():
				return
			}
		}
	}()

	go func() {
		wg.Wait()
		client.Close()
		cancel()
		close(chOut)
	}()

	return chOut, nil
}
