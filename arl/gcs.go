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
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"strings"
	"sync"

	"cloud.google.com/go/storage"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
)

func (a AuthenticatedResourceLocator) getGCS() (chan Content, error) {
	authBlob, err := base64.StdEncoding.DecodeString(a.authData)
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	client, err := storage.NewClient(ctx, option.WithCredentialsJSON([]byte(authBlob)))
	if err != nil {
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
	for {
		attrs, err := it.Next()
		if err == iterator.Done {
			break
		}
		blobs = append(blobs, attrs)
	}

	chOut := make(chan Content)
	chIn := make(chan *storage.ObjectAttrs)
	wg := sync.WaitGroup{}

	for i := uint64(0); i < a.maxConcurrent; i++ {
		go func() {
			for o := range chIn {
				out := Content{
					FilePath: fmt.Sprintf("gcs://%s/%s", bucketName, o.Name),
				}
				reader, err := bucket.Object(o.Name).NewReader(ctx)
				if err != nil {
					out.Error = err
					chOut <- out
					continue
				}
				b := bytes.Buffer{}
				_, err = io.Copy(&b, reader)
				if err != nil {
					out.Error = err
					out.Data = b.Bytes()
					chOut <- out
					continue
				}
				reader.Close()
				out.Data = b.Bytes()

				// If there was only one blob, we check if
				// it's an archive and multiplex it.
				if len(blobs) == 1 {
					for b := range multiplexContent(out) {
						chOut <- b
					}
					continue
				}
				chOut <- out
			}
			wg.Done()
		}()
		wg.Add(1)
	}

	go func() {
		for _, b := range blobs {
			chIn <- b
		}
		close(chIn)
	}()

	go func() {
		wg.Wait()
		close(chOut)
	}()

	return chOut, nil
}
