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
	"errors"
	"fmt"
	"io"
	"strings"
)

type AuthenticatedResourceLocator struct {
	arl           string
	maxSize       uint64
	maxConcurrent uint64

	methodName string
	methodDest string
	authType   string
	authData   string

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
		"":      true,
	},
}

func NewARL(arl string, maxSize uint64, maxConcurrent uint64) (AuthenticatedResourceLocator, error) {
	a := AuthenticatedResourceLocator{
		arl:           arl,
		maxSize:       maxSize,
		maxConcurrent: maxConcurrent,
	}

	if strings.HasPrefix(arl, "https://") {
		// This is a shortcut for backwards compatibility.
		a.methodName = "https"
		a.methodDest = arl
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

func (a *AuthenticatedResourceLocator) Fetch() (chan Content, error) {
	return a.get()
}

func multiplexContent(c Content) chan Content {
	out := make(chan Content, 1)

	go func() {
		defer close(out)

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
			newData := bytes.Buffer{}
			_, err = io.Copy(&newData, tarReader)
			out <- Content{
				FilePath: fmt.Sprintf("/%s", header.Name),
				Data:     newData.Bytes(),
				Error:    err,
			}
		}

		zipReader, err := zip.NewReader(bytes.NewReader(c.Data), int64(len(c.Data)))
		if err != nil {
			// So this was not a tar and not a zip, we'll just return
			// the file as-is.
			out <- c
			return
		}
		for _, zipFile := range zipReader.File {
			newData := bytes.Buffer{}
			newFile := Content{
				FilePath: fmt.Sprintf("/%s", zipFile.Name),
			}
			f, err := zipFile.Open()
			if err != nil {
				newFile.Error = err
			} else {
				_, err = io.Copy(&newData, f)
			}
			if err != nil {
				newFile.Error = err
			} else {
				newFile.Data = newData.Bytes()
			}
			out <- newFile
		}
	}()

	return out
}
