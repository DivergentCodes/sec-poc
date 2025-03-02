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
	"sort"
	"strings"
	"sync"

	"github.com/Masterminds/semver/v3"
)

var (
	silent            = false
	verbose           = false
	processedPackages sync.Map
)

// PackageInfo holds metadata, script hooks, depth, and dependency chain
type PackageInfo struct {
	Name    string            `json:"name"`
	Version string            `json:"version"`
	Scripts map[string]string `json:"scripts"`
	Depth   int               `json:"depth"`
	Chain   []string          `json:"chain"`
}

// PackageLock represents the structure of package-lock.json
type PackageLock struct {
	Name         string                    `json:"name"`
	Version      string                    `json:"version"`
	Dependencies map[string]PackageLockDep `json:"dependencies,omitempty"`
	Packages     map[string]PackageLockDep `json:"packages,omitempty"`
}

// Update PackageLockDep to handle string dependencies
type PackageLockDep struct {
	Version      string      `json:"version"`
	Dependencies interface{} `json:"dependencies,omitempty"` // Can be map[string]PackageLockDep or string
}

// Add helper function to convert interface{} dependencies to map
func convertDependencies(deps interface{}) map[string]PackageLockDep {
	if deps == nil {
		return nil
	}

	switch d := deps.(type) {
	case map[string]interface{}:
		result := make(map[string]PackageLockDep)
		for name, dep := range d {
			if depMap, ok := dep.(map[string]interface{}); ok {
				result[name] = PackageLockDep{
					Version:      depMap["version"].(string),
					Dependencies: depMap["dependencies"],
				}
			}
		}
		return result
	default:
		return nil
	}
}

// Lifecycle scripts to capture
var lifecycleScripts = map[string]bool{
	"preinstall":    true,
	"postinstall":   true,
	"preuninstall":  true,
	"postuninstall": true,
	"preprepare":    true,
	"postprepare":   true,
	"prepublish":    true,
	"postpublish":   true,
	"prestart":      true,
	"poststart":     true,
	"prerestart":    true,
	"postrestart":   true,
	"prestop":       true,
	"poststop":      true,
	"pretest":       true,
	"posttest":      true,
	"prepack":       true,
	"postpack":      true,
	"preversion":    true,
	"postversion":   true,
}

// Add new type for NPM registry response
type NpmRegistryResponse struct {
	Versions map[string]struct {
		Dependencies map[string]string `json:"dependencies"`
	} `json:"versions"`
}

// Update getPackageMetadata to return all versions
func getPackageVersions(pkg string) (map[string]map[string]string, error) {
	url := fmt.Sprintf("https://registry.npmjs.org/%s", pkg)
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch package metadata: %s", resp.Status)
	}

	var npmResp NpmRegistryResponse
	if err := json.NewDecoder(resp.Body).Decode(&npmResp); err != nil {
		return nil, err
	}

	result := make(map[string]map[string]string)
	for version, data := range npmResp.Versions {
		result[version] = data.Dependencies
	}
	return result, nil
}

// Add function to resolve version constraint
func resolveVersion(pkg, constraint string, versions map[string]map[string]string) (string, map[string]string, error) {
	// Handle exact versions (those starting with = or not having any constraint)
	if strings.HasPrefix(constraint, "=") || !strings.ContainsAny(constraint, "^~><= ") {
		cleanVersion := strings.TrimPrefix(constraint, "=")
		if deps, ok := versions[cleanVersion]; ok {
			return cleanVersion, deps, nil
		}
		return "", nil, fmt.Errorf("exact version %s not found", cleanVersion)
	}

	// Parse constraint
	c, err := semver.NewConstraint(constraint)
	if err != nil {
		return "", nil, fmt.Errorf("invalid version constraint %s: %v", constraint, err)
	}

	// Convert versions to semver.Version objects
	var validVersions []*semver.Version
	for v := range versions {
		sv, err := semver.NewVersion(v)
		if err != nil {
			continue // Skip invalid versions
		}
		validVersions = append(validVersions, sv)
	}

	// Sort versions in descending order
	sort.Slice(validVersions, func(i, j int) bool {
		return validVersions[i].GreaterThan(validVersions[j])
	})

	// Find highest matching version
	for _, v := range validVersions {
		if c.Check(v) {
			vStr := v.String()
			return vStr, versions[vStr], nil
		}
	}

	return "", nil, fmt.Errorf("no version matching constraint %s", constraint)
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

// Generate the correct tarball URL for both namespaced and non-namespaced packages
func makeNpmTarballURL(pkg, version string) string {
	if strings.HasPrefix(pkg, "@") {
		namespace := pkg[:strings.Index(pkg, "/")]
		packageName := pkg[strings.Index(pkg, "/")+1:]
		return fmt.Sprintf("https://registry.npmjs.org/%s/%s/-/%s-%s.tgz", namespace, packageName, packageName, version)
	}
	return fmt.Sprintf("https://registry.npmjs.org/%s/-/%s-%s.tgz", pkg, pkg, version)
}

// Fetch package.json from an NPM package tarball
func getLifecycleScripts(pkg, version string) (map[string]string, error) {
	url := makeNpmTarballURL(pkg, version)
	if verbose {
		fmt.Printf("⬇️ Fetching tarball for %s @ %s from: %s\n", pkg, version, url)
	}

	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch package tarball: %s", resp.Status)
	}

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

			lifecycleOnly := make(map[string]string)
			for key, value := range pkgJSON.Scripts {
				if lifecycleScripts[key] {
					lifecycleOnly[key] = value
				}
			}

			if len(lifecycleOnly) > 0 {
				return lifecycleOnly, nil
			}
		}
	}

	return nil, nil
}

// Add new function to get package-lock.json from an NPM package tarball
func getPackageLock(pkg, version string) (*PackageLock, error) {
	url := makeNpmTarballURL(pkg, version)
	if verbose {
		fmt.Printf("⬇️ Fetching tarball for %s @ %s from: %s\n", pkg, version, url)
	}

	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch package tarball: %s", resp.Status)
	}

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

		if header.Name == "package/package-lock.json" {
			var lockFile PackageLock
			if err := json.NewDecoder(tarReader).Decode(&lockFile); err != nil {
				return nil, err
			}
			return &lockFile, nil
		}
	}

	return nil, fmt.Errorf("package-lock.json not found in package tarball")
}

// Process dependencies from package-lock.json
func processLockDependencies(deps map[string]PackageLockDep, chain []string, depth int, wg *sync.WaitGroup, results chan<- PackageInfo) {
	for pkg, dep := range deps {
		wg.Add(1)
		go func(pkg string, dep PackageLockDep) {
			defer wg.Done()

			pkgIdentifier := fmt.Sprintf("%s@%s", pkg, dep.Version)

			if _, exists := processedPackages.Load(pkgIdentifier); exists {
				if verbose {
					fmt.Printf("📦 Skipping already processed package: %s\n", pkgIdentifier)
				}
				return
			}
			processedPackages.Store(pkgIdentifier, true)

			scripts, err := getLifecycleScripts(pkg, dep.Version)
			if err != nil {
				fmt.Fprintf(os.Stderr, "❌ Error fetching scripts for %s @ %s: %v\n", pkg, dep.Version, err)
				return
			}

			fullChain := append(chain, pkgIdentifier)
			if scripts != nil {
				results <- PackageInfo{
					Name:    pkg,
					Version: dep.Version,
					Scripts: scripts,
					Depth:   depth,
					Chain:   fullChain,
				}
			}

			// Convert and process nested dependencies
			if nestedDeps := convertDependencies(dep.Dependencies); nestedDeps != nil {
				processLockDependencies(nestedDeps, fullChain, depth+1, wg, results)
			}

			if !silent {
				fmt.Printf("✅ Processed %s @ %s\n", pkg, dep.Version)
			}
		}(pkg, dep)
	}
}

// Update processNpmPackage to handle "latest" version
func processNpmPackage(pkg string, versionConstraint string, chain []string, depth int, wg *sync.WaitGroup, results chan<- PackageInfo) {
	defer wg.Done()

	// Get all versions and their dependencies
	versions, err := getPackageVersions(pkg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ Error fetching versions for %s: %v\n", pkg, err)
		return
	}

	var version string
	var deps map[string]string

	// Handle "latest" version specially
	if versionConstraint == "latest" {
		latestVersion, err := getPackageMetadata(pkg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "❌ Error fetching latest version for %s: %v\n", pkg, err)
			return
		}
		version = latestVersion
		deps = versions[latestVersion]
	} else {
		// Resolve other version constraints
		resolvedVersion, resolvedDeps, err := resolveVersion(pkg, versionConstraint, versions)
		if err != nil {
			fmt.Fprintf(os.Stderr, "❌ Error resolving version for %s @ %s: %v\n", pkg, versionConstraint, err)
			return
		}
		version = resolvedVersion
		deps = resolvedDeps
	}

	pkgIdentifier := fmt.Sprintf("%s@%s", pkg, version)

	// Check if already processed
	if _, exists := processedPackages.Load(pkgIdentifier); exists {
		if verbose {
			fmt.Printf("📦 Skipping already processed package: %s\n", pkgIdentifier)
		}
		return
	}
	processedPackages.Store(pkgIdentifier, true)

	// Get lifecycle scripts
	scripts, err := getLifecycleScripts(pkg, version)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ Error fetching scripts for %s @ %s: %v\n", pkg, version, err)
		return
	}

	fullChain := append(chain, pkgIdentifier)
	if scripts != nil {
		results <- PackageInfo{
			Name:    pkg,
			Version: version,
			Scripts: scripts,
			Depth:   depth,
			Chain:   fullChain,
		}
	}

	// Process dependencies recursively
	for depName, depVersion := range deps {
		wg.Add(1)
		go processNpmPackage(depName, depVersion, fullChain, depth+1, wg, results)
	}

	if verbose {
		fmt.Printf("✅ Processed %s @ %s\n", pkg, version)
	}
}

func main() {
	defaultPath := filepath.Join(".", "package-lock.json")
	lockFilePath := flag.String("lockfile", defaultPath, "Path to package-lock.json file")
	npmPackage := flag.String("npm", "", "NPM package to analyze (optional)")
	npmVersion := flag.String("version", "", "NPM package version (optional, defaults to latest)")
	silentFlag := flag.Bool("silent", false, "Enable silent output")
	verboseFlag := flag.Bool("verbose", false, "Enable verbose output")
	flag.Parse()

	silent = *silentFlag
	verbose = *verboseFlag
	if verbose && silent {
		fmt.Println("Silent and verbose flags cannot be used together")
		os.Exit(1)
	}
	if verbose {
		fmt.Println("Verbose output enabled")
	}

	if !silent {
		fmt.Println("🔍 NPM Script Hook Detection Tool")
		fmt.Println("Analyzing dependencies for potentially malicious lifecycle scripts...")
		fmt.Println()
	}

	var results = make(chan PackageInfo, 100)
	var wg sync.WaitGroup

	if *npmPackage != "" {
		version := *npmVersion
		if version == "" {
			version = "latest"
		}

		wg.Add(1)
		go processNpmPackage(*npmPackage, version, []string{}, 0, &wg, results)
	} else {
		fmt.Printf("🔍 Analyzing lockfile: %s\n", *lockFilePath)

		file, err := os.Open(*lockFilePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "❌ Error opening package-lock.json: %v\n", err)
			os.Exit(1)
		}
		defer file.Close()

		var lockFile PackageLock
		if err := json.NewDecoder(file).Decode(&lockFile); err != nil {
			fmt.Fprintf(os.Stderr, "❌ Error parsing package-lock.json: %v\n", err)
			os.Exit(1)
		}

		// Handle both old and new package-lock.json formats
		if len(lockFile.Dependencies) > 0 {
			processLockDependencies(lockFile.Dependencies, []string{}, 1, &wg, results)
		} else if len(lockFile.Packages) > 0 {
			// Convert packages to the same format as dependencies
			deps := make(map[string]PackageLockDep)
			for path, pkg := range lockFile.Packages {
				if path == "" || path == "node_modules" {
					continue // Skip root package and node_modules directory
				}

				// Clean up the package name by removing node_modules/ prefix and any nested node_modules
				name := path
				if strings.HasPrefix(name, "node_modules/") {
					name = strings.TrimPrefix(name, "node_modules/")
				}
				// Handle nested node_modules paths
				parts := strings.Split(name, "node_modules/")
				name = parts[len(parts)-1]

				deps[name] = pkg
			}
			processLockDependencies(deps, []string{}, 1, &wg, results)
		}
	}

	// Create a goroutine to close results after all work is done
	go func() {
		wg.Wait()
		close(results)
	}()

	// Initialize empty slice to ensure we don't output null
	packageInfos := []PackageInfo{}

	// Collect results
	for pkgInfo := range results {
		packageInfos = append(packageInfos, pkgInfo)
	}

	jsonOutput, _ := json.MarshalIndent(packageInfos, "", "  ")
	fmt.Println(string(jsonOutput))
}
