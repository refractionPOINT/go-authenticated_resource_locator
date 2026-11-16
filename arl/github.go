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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

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
	cloneCtx, cancelClone := context.WithTimeout(context.Background(), a.opts.timeoutOr(tarballFetchTimeout))
	defer cancelClone()
	r, err := git.CloneContext(cloneCtx, memory.NewStorage(), nil, &gitOptions)
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
			data, err := readLimited(reader, a.maxSize)
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

// tarballFetchTimeout bounds the life of a tarball transfer so that an
// abandoned consumer cannot pin the underlying connection forever.
const tarballFetchTimeout = 30 * time.Minute

// getGitHubFromTarball fetches the tree of a public GitHub repo at the tip of
// a branch (or the default branch) as a streamed tarball. Unlike a git clone,
// this holds at most one file in memory at a time and never fetches history.
func (a AuthenticatedResourceLocator) getGitHubFromTarball(repoPath string, pathInRepo string, targetBranch string) (chan Content, error) {
	ref := "HEAD"
	if targetBranch != "" {
		ref = fmt.Sprintf("refs/heads/%s", targetBranch)
	}
	url := fmt.Sprintf("https://codeload.github.com/%s/tar.gz/%s", repoPath, ref)

	ctx, cancel := context.WithTimeout(context.Background(), a.opts.timeoutOr(tarballFetchTimeout))
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		cancel()
		return nil, err
	}
	req.Header.Set("User-Agent", "AuthenticatedResourceLocator/Go")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to fetch repo tarball: %v", err)
	}
	if resp.StatusCode != 200 {
		resp.Body.Close()
		cancel()
		return nil, fmt.Errorf("failed to fetch repo tarball %s: %s", url, resp.Status)
	}

	gzReader, err := gzip.NewReader(resp.Body)
	if err != nil {
		resp.Body.Close()
		cancel()
		return nil, fmt.Errorf("failed to read repo tarball: %v", err)
	}

	chOut := make(chan Content, a.maxConcurrent)
	go func() {
		defer close(chOut)
		defer cancel()
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
			data, err := readLimited(tarReader, a.maxSize)
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

	ctx, cancel := context.WithTimeout(context.Background(), a.opts.timeoutOr(defaultHTTPTimeout))
	gh := &githubFetcher{ctx: ctx, client: a.httpClient, maxSize: a.maxSize, auth: authHeaders}

	paths, err := gh.listFiles(fullURL, repoPath, repoParams)

	if err != nil {
		cancel()
		return nil, err
	}

	// If we have a single content, multiplex it.
	if len(paths) == 1 {
		defer cancel()
		data, err := gh.download(paths[0].DownloadURL)
		if err != nil {
			return nil, err
		}
		tmpContent := Content{
			FilePath: paths[0].Path,
			Data:     data,
		}
		return multiplexContent(tmpContent, a.maxSize), nil
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
				data, err := gh.download(gr.DownloadURL)
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
		cancel()
		close(chOut)
	}()

	return chOut, nil
}

// githubFetcher holds the shared state of the REST API calls of one fetch.
type githubFetcher struct {
	ctx     context.Context
	client  *http.Client
	maxSize uint64
	auth    http.Header

	// totalListed is the sum of the file sizes found while listing.
	totalListed uint64
}

func (g *githubFetcher) listFiles(baseURL string, subPath string, repoParams string) ([]githubFileRecord, error) {
	outPaths := []githubFileRecord{}

	thisURL := fmt.Sprintf("%s%s%s", baseURL, subPath, repoParams)
	body, err := g.download(thisURL)
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

			subPaths, err := g.listFiles(baseURL, thisPath, repoParams)
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
				if entrySize < 0 || uint64(entrySize) > g.maxSize {
					return outPaths, ErrorResourceTooLarge
				}
				g.totalListed += uint64(entrySize)
				if g.totalListed > g.maxSize {
					return outPaths, ErrorResourceTooLarge
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

func (g *githubFetcher) download(url string) ([]byte, error) {
	if !strings.HasPrefix(url, "https://") {
		return nil, fmt.Errorf("refusing non https github url: %s", url)
	}

	req, err := http.NewRequestWithContext(g.ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	// Copy the headers since they're not thread safe.
	headers := http.Header{}
	for k, v := range g.auth {
		headers[k] = v
	}
	req.Header = headers
	req.Header.Set("User-Agent", "AuthenticatedResourceLocator/Go")

	resp, err := g.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("failed to get resource %s: %s", url, resp.Status)
	}

	return readLimited(resp.Body, g.maxSize)
}
