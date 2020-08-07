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
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"sync"
)

type githubFileRecord struct {
	Path        string
	DownloadURL string
}

func (a AuthenticatedResourceLocator) getGitHub() (chan Content, error) {
	repoParams := ""

	if strings.Contains(a.methodDest, "?") {
		components := strings.SplitN(a.methodDest, "?", 2)
		if len(components) != 2 {
			return nil, errors.New("invalid github path")
		}
		newRoot := components[0]
		repoParams = components[1]

		a.methodDest = newRoot
		repoParams = fmt.Sprintf("?%s", repoParams)
	}

	repoPath := ""
	components := strings.SplitN(a.methodDest, "/", 3)
	if len(components) == 2 {
		repoPath = ""
	} else if len(components) == 3 {
		repoPath = components[2]
	} else {
		return nil, errors.New("github destination should be \"repoOwner/repoName\" or \"repoOwner/repoName/repoSubDir\".")
	}

	repoOwner := components[0]
	repoName := components[1]

	if strings.HasSuffix(repoPath, "/") {
		repoPath = repoPath[0 : len(repoPath)-1]
	}

	fullURL := fmt.Sprintf("https://api.github.com/repos/%s/%s/contents/", repoOwner, repoName)

	authHeaders := http.Header{}
	if a.authType == "" {
		// Nothing to do.
	} else if a.authType == "token" {
		authHeaders.Add("Authorization", fmt.Sprintf("token %s", a.authData))
	} else {
		return nil, ErrorAuthNotImplemented
	}

	paths, err := listGithubFiles(a.maxSize, fullURL, authHeaders, repoPath, repoParams)

	if err != nil {
		return nil, err
	}

	// If we have a single content, multiplex it.
	if len(paths) == 1 {
		data, err := downloadGithubFile(paths[0].DownloadURL, authHeaders)
		if err != nil {
			return nil, err
		}
		tmpContent := Content{
			FilePath: paths[0].Path,
			Data:     data,
		}
		return multiplexContent(tmpContent), nil
	}

	chIn := make(chan githubFileRecord, len(paths))

	for _, p := range paths {
		chIn <- p
	}
	close(chIn)

	chOut := make(chan Content, a.maxConcurrent)
	wg := sync.WaitGroup{}

	for i := 0; uint64(i) < a.maxConcurrent; i++ {
		wg.Add(1)

		go func() {
			defer wg.Done()

			for gr := range chIn {
				tmpContent := Content{
					FilePath: gr.Path,
				}
				data, err := downloadGithubFile(gr.DownloadURL, authHeaders)
				if err != nil {
					tmpContent.Error = err
					chOut <- tmpContent
					return
				}
				tmpContent.Data = data
				chOut <- tmpContent
			}
		}()
	}

	go func(){
		wg.Wait()
		close(chOut)
	}()

	return chOut, nil
}

func listGithubFiles(maxSize uint64, baseURL string, auth http.Header, subPath string, repoParams string) ([]githubFileRecord, error) {
	outPaths := []githubFileRecord{}

	sep := ""
	if subPath != "" {
		sep = "/"
	}

	thisURL := fmt.Sprintf("%s%s%s%s", baseURL, sep, subPath, repoParams)
	
	body, err := downloadGithubFile(thisURL, auth)
	if err != nil {
		return outPaths, err
	}

	// If the listing path was a single file
	// we normalize it.
	var jsonResponse interface{}
	if err := json.Unmarshal(body, &jsonResponse); err != nil {
		return outPaths, fmt.Errorf("failed parsing %s: %v", thisURL, err)
	}

	files := []interface{}{}
	if f, ok := jsonResponse.(map[string]interface{}); ok {
		files = append(files, f)
	} else if f, ok := jsonResponse.([]interface{}); ok {
		files = f
	}

	// Recurse as needed.
	for _, f := range files {
		fileEntry, ok := f.(map[string]interface{})
		if !ok {
			return outPaths, fmt.Errorf("unexpected json data: %T", fileEntry)
		}
		entryType, okType := fileEntry["type"]
		if !okType {
			return outPaths, errors.New("github data missing type")
		}

		var thisPath string
		var okPath bool
		if v, ok := fileEntry["path"]; ok {
			thisPath, okPath = v.(string)
		}

		if entryType == "dir" {
			if !okPath {
				return outPaths, errors.New("github data missing path")
			}

			subPaths, err := listGithubFiles(maxSize, baseURL, auth, thisPath, repoParams)
			outPaths = append(outPaths, subPaths...)
			if err != nil {
				return outPaths, err
			}
		} else if entryType == "file" {
			if !okPath {
				return outPaths, errors.New("github data missing path")
			}

			var entrySize float64
			var okSize bool
			if v, ok := fileEntry["size"]; ok {
				entrySize, okSize = v.(float64)
			}

			if !okSize {
				return outPaths, errors.New("github data missing size")
			}

			var thisDownload string
			var okDownload bool
			if v, ok := fileEntry["download_url"]; ok {
				thisDownload, okDownload = v.(string)
			}

			if !okDownload {
				return outPaths, errors.New("github data missing download_url")
			}

			if entrySize != 0 {
				if maxSize != 0 && uint64(entrySize) > maxSize {
					return outPaths, errors.New("Maximum resurce size reached.")
				}
				outPaths = append(outPaths, githubFileRecord{
					Path:        thisPath,
					DownloadURL: thisDownload,
				})
			}
		}
	}

	return outPaths, nil
}

func downloadGithubFile(url string, auth http.Header) ([]byte, error) {
	data := []byte{}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return data, err
	}
	req.Header = auth

	client := http.Client{}

	resp, err := client.Do(req)
	if err != nil {
		return data, err
	}

	if resp.StatusCode != 200 {
		return data, fmt.Errorf("failed to get resource %s: %s", url, resp.Status)
	}

	data, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return data, err
	}

	return data, nil
}
