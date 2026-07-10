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
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strings"
	"sync"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/transport/ssh"
	"github.com/go-git/go-git/v5/storage/memory"
)

type githubFileRecord struct {
	Path        string
	DownloadURL string
}

func (a AuthenticatedResourceLocator) getGitHub() (chan Content, error) {
	if a.authType == "" || a.authType == "ssh" {
		// If there is no auth, we can use the git package.
		return a.getGitHubFromGit()
	}

	// With a token, use the API.
	return a.getGitHubFromAPI()
}

func (a AuthenticatedResourceLocator) getGitHubFromGit() (chan Content, error) {
	// If the path in repo ends with "?ref=...", we extract the
	// ref name we want to look for.
	targetBranch := ""
	pathInRepo := ""
	dest := a.methodDest
	if strings.Contains(a.methodDest, "?ref=") {
		components := strings.SplitN(a.methodDest, "?ref=", 2)
		if len(components) != 2 {
			return nil, errors.New("invalid github path")
		}
		dest = components[0]
		targetBranch = components[1]
	}

	// Get the repo name itself. It's the first 2 components.
	components := strings.Split(dest, "/")
	if len(components) < 2 {
		return nil, errors.New(`github destination should be "repoOwner/repoName" or "repoOwner/repoName/repoSubDir"`)
	}
	repoPath := strings.Join(components[:2], "/")
	if len(components) > 2 {
		pathInRepo = strings.Join(components[2:], "/")
	}

	if a.authType == "" {
		// Public repo: stream a tarball of the tree at HEAD instead of
		// cloning, a clone materializes the full history in memory.
		return a.getGitHubFromTarball(repoPath, pathInRepo, targetBranch)
	}

	gitOptions := git.CloneOptions{
		URL: fmt.Sprintf("git@github.com:%s", repoPath),
		// We only ever read the tree at the tip of one branch, a full
		// clone would hold the entire history in memory.
		Depth:        1,
		SingleBranch: true,
	}
	if targetBranch != "" {
		gitOptions.ReferenceName = plumbing.ReferenceName(fmt.Sprintf("refs/heads/%s", targetBranch))
	}

	pubKey, err := ssh.NewPublicKeys("git", []byte(a.authData), "")
	if err != nil {
		return nil, fmt.Errorf("generate publickey failed: %v", err)
	}
	gitOptions.Auth = pubKey

	// Clone the repo in memory.
	r, err := git.Clone(memory.NewStorage(), nil, &gitOptions)
	if err != nil {
		return nil, fmt.Errorf("failed to clone repo: %v", err)
	}

	// We default to the HEAD.
	ref, err := r.Head()
	if err != nil {
		return nil, fmt.Errorf("failed to get HEAD: %v", err)
	}

	// Get the commit object at HEAD.
	commit, err := r.CommitObject(ref.Hash())
	if err != nil {
		return nil, fmt.Errorf("failed to get commit: %v", err)
	}

	// Get the tree at the commit.
	tree, err := commit.Tree()
	if err != nil {
		return nil, fmt.Errorf("failed to get tree: %v", err)
	}

	// Start iterating through all the files.
	chOut := make(chan Content, a.maxConcurrent)
	go func() {
		defer close(chOut)
		totalSize := uint64(0)
		err := tree.Files().ForEach(func(f *object.File) error {
			if !strings.HasPrefix(f.Name, pathInRepo) {
				return nil
			}
			if a.maxSize != 0 {
				totalSize += uint64(f.Size)
				if totalSize > a.maxSize {
					return fmt.Errorf("maximum resource size reached (%d bytes)", a.maxSize)
				}
			}
			reader, err := f.Blob.Reader()
			if err != nil {
				return fmt.Errorf("failed to get blob reader: %v", err)
			}
			data, err := ioutil.ReadAll(reader)
			reader.Close()
			if err != nil {
				return fmt.Errorf("failed to read blob: %v", err)
			}
			chOut <- Content{
				FilePath: f.Name,
				Data:     data,
			}
			return nil
		})
		if err != nil {
			chOut <- Content{Error: err}
		}
	}()

	return chOut, nil
}

// getGitHubFromTarball fetches the tree of a public GitHub repo at the tip of
// a branch (or the default branch) as a streamed tarball. Unlike a git clone,
// this holds at most one file in memory at a time and never fetches history.
func (a AuthenticatedResourceLocator) getGitHubFromTarball(repoPath string, pathInRepo string, targetBranch string) (chan Content, error) {
	ref := "HEAD"
	if targetBranch != "" {
		ref = fmt.Sprintf("refs/heads/%s", targetBranch)
	}
	url := fmt.Sprintf("https://codeload.github.com/%s/tar.gz/%s", repoPath, ref)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "AuthenticatedResourceLocator/Go")

	client := a.httpClient
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch repo tarball: %v", err)
	}
	if resp.StatusCode != 200 {
		resp.Body.Close()
		return nil, fmt.Errorf("failed to fetch repo tarball %s: %s", url, resp.Status)
	}

	gzReader, err := gzip.NewReader(resp.Body)
	if err != nil {
		resp.Body.Close()
		return nil, fmt.Errorf("failed to read repo tarball: %v", err)
	}

	chOut := make(chan Content, a.maxConcurrent)
	go func() {
		defer close(chOut)
		defer resp.Body.Close()
		defer gzReader.Close()

		totalSize := uint64(0)
		tarReader := tar.NewReader(gzReader)
		for {
			header, err := tarReader.Next()
			if err == io.EOF {
				return
			}
			if err != nil {
				chOut <- Content{Error: fmt.Errorf("failed to read repo tarball: %v", err)}
				return
			}
			// We only care about regular files.
			if header.Typeflag != tar.TypeReg {
				continue
			}
			// GitHub tarballs prefix every entry with a top level
			// "repoName-ref/" directory, strip it to get the path in repo.
			name := header.Name
			idx := strings.Index(name, "/")
			if idx < 0 {
				continue
			}
			name = name[idx+1:]
			if name == "" || !strings.HasPrefix(name, pathInRepo) {
				continue
			}
			if a.maxSize != 0 {
				totalSize += uint64(header.Size)
				if totalSize > a.maxSize {
					chOut <- Content{Error: fmt.Errorf("maximum resource size reached (%d bytes)", a.maxSize)}
					return
				}
			}
			data, err := io.ReadAll(tarReader)
			if err != nil {
				chOut <- Content{FilePath: name, Error: fmt.Errorf("failed to read %s from repo tarball: %v", name, err)}
				return
			}
			chOut <- Content{
				FilePath: name,
				Data:     data,
			}
		}
	}()

	return chOut, nil
}

func (a AuthenticatedResourceLocator) getGitHubFromAPI() (chan Content, error) {
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
		return nil, errors.New(`github destination should be "repoOwner/repoName" or "repoOwner/repoName/repoSubDir"`)
	}

	repoOwner := components[0]
	repoName := components[1]

	repoPath = strings.TrimSuffix(repoPath, "/")

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

	go func() {
		wg.Wait()
		close(chOut)
	}()

	return chOut, nil
}

func listGithubFiles(maxSize uint64, baseURL string, auth http.Header, subPath string, repoParams string) ([]githubFileRecord, error) {
	outPaths := []githubFileRecord{}

	thisURL := fmt.Sprintf("%s%s%s", baseURL, subPath, repoParams)
	fmt.Println(thisURL)
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

	// Copy the headers since they're not thread safe.
	headers := http.Header{}
	for k, v := range auth {
		headers[k] = v
	}
	req.Header = headers
	req.Header.Set("User-Agent", "AuthenticatedResourceLocator/Go")

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
