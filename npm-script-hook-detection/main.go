package main

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
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

// Fetch package metadata from the NPM registry
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

// Fetch package.json from an NPM package
func fetchPackageJSON(pkg, version string) (map[string]interface{}, error) {
	url := fmt.Sprintf("https://registry.npmjs.org/%s/%s", pkg, version)
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var packageData map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&packageData); err != nil {
		return nil, err
	}

	return packageData, nil
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

// Parse dependencies from a package.json map
func parseDependencies(pkgData map[string]interface{}) []string {
	uniquePackages := make(map[string]bool)

	if dependencies, ok := pkgData["dependencies"].(map[string]interface{}); ok {
		for dep := range dependencies {
			uniquePackages[dep] = true
		}
	}
	if devDependencies, ok := pkgData["devDependencies"].(map[string]interface{}); ok {
		for dep := range devDependencies {
			uniquePackages[dep] = true
		}
	}

	var packages []string
	for pkg := range uniquePackages {
		packages = append(packages, pkg)
	}

	return packages
}

// Parse dependencies from a local package.json file
func getDependenciesFromFile(packageJSONPath string) ([]string, error) {
	file, err := os.Open(packageJSONPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var pkg map[string]interface{}
	if err := json.NewDecoder(file).Decode(&pkg); err != nil {
		return nil, err
	}

	return parseDependencies(pkg), nil
}

// Process an individual package
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
	// Default to package.json in the current directory
	defaultPath := filepath.Join(".", "package.json")
	packageJSONPath := flag.String("package", defaultPath, "Path to package.json file")
	npmPackage := flag.String("npm", "", "NPM package to use as the starting point")
	flag.Parse()

	var packages []string
	var err error

	if *npmPackage != "" {
		// Fetch dependencies from the specified NPM package
		version, err := getPackageMetadata(*npmPackage)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error fetching metadata for %s: %v\n", *npmPackage, err)
			os.Exit(1)
		}

		pkgData, err := fetchPackageJSON(*npmPackage, version)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error fetching package.json for %s: %v\n", *npmPackage, err)
			os.Exit(1)
		}

		packages = parseDependencies(pkgData)
	} else {
		// Read dependencies from a local package.json
		packages, err = getDependenciesFromFile(*packageJSONPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading dependencies: %v\n", err)
			os.Exit(1)
		}
	}

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
