package main

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
)

// Lifecycle scripts to capture
var lifecycleScripts = map[string]bool{
	"preinstall":    true,
	"install":       true,
	"postinstall":   true,
	"preuninstall":  true,
	"uninstall":     true,
	"postuninstall": true,
	"prepack":       true,
	"postpack":      true,
}

// PackageInfo holds metadata and script hooks
type PackageInfo struct {
	Name    string            `json:"name"`
	Version string            `json:"version"`
	Scripts map[string]string `json:"scripts"`
}

// Fetches package metadata from the NPM registry
func getPackageMetadata(pkg string) (string, error) {
	url := fmt.Sprintf("https://registry.npmjs.org/%s", pkg)
	resp, err := http.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var metadata struct {
		DistTags struct {
			Latest string `json:"latest"`
		} `json:"dist-tags"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&metadata); err != nil {
		return "", err
	}

	return metadata.DistTags.Latest, nil
}

// Reads package.json inside a .tgz file without extracting
func getLifecycleScripts(pkg, version string) (map[string]string, error) {
	url := fmt.Sprintf("https://registry.npmjs.org/%s/-/%s-%s.tgz", pkg, pkg, version)
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	gzipReader, err := gzip.NewReader(resp.Body)
	if err != nil {
		return nil, err
	}
	tarReader := tar.NewReader(gzipReader)

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		if header.Name == "package/package.json" {
			var pkgJSON struct {
				Scripts map[string]string `json:"scripts"`
			}
			if err := json.NewDecoder(tarReader).Decode(&pkgJSON); err != nil {
				return nil, err
			}

			// Filter only lifecycle scripts
			lifecycleOnly := make(map[string]string)
			for key, value := range pkgJSON.Scripts {
				if lifecycleScripts[key] {
					lifecycleOnly[key] = value
				}
			}

			// Return only if lifecycle scripts exist
			if len(lifecycleOnly) > 0 {
				return lifecycleOnly, nil
			}
		}
	}

	return nil, nil // No lifecycle scripts found
}

func processPackage(pkg string, wg *sync.WaitGroup, results chan<- PackageInfo) {
	defer wg.Done()

	version, err := getPackageMetadata(pkg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error fetching metadata for %s: %v\n", pkg, err)
		return
	}

	scripts, err := getLifecycleScripts(pkg, version)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error fetching scripts for %s: %v\n", pkg, err)
		return
	}

	if scripts != nil {
		results <- PackageInfo{Name: pkg, Version: version, Scripts: scripts}
	}
}

func main() {
	packages := []string{"express", "lodash", "react"} // Example package list

	var wg sync.WaitGroup
	results := make(chan PackageInfo, len(packages))

	for _, pkg := range packages {
		wg.Add(1)
		go processPackage(pkg, &wg, results)
	}

	wg.Wait()
	close(results)

	var packageInfos []PackageInfo
	for pkgInfo := range results {
		packageInfos = append(packageInfos, pkgInfo)
	}

	// Print JSON output
	jsonOutput, _ := json.MarshalIndent(packageInfos, "", "  ")
	fmt.Println(string(jsonOutput))
}
