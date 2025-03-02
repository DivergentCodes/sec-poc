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
	"strings"
	"sync"
)

// Lifecycle scripts to capture
var lifecycleScripts = map[string]bool{
	"preinstall":  true,
	"postinstall": true,

	"preuninstall":  true,
	"postuninstall": true,

	"preprepare":  true,
	"postprepare": true,

	"prepublish":  true,
	"postpublish": true,

	"prestart":  true,
	"poststart": true,

	"prerestart":  true,
	"postrestart": true,

	"prestop":  true,
	"poststop": true,

	"pretest":  true,
	"posttest": true,

	"prepack":  true,
	"postpack": true,

	"preversion":  true,
	"postversion": true,
}

var (
	verbose = false

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

// Generate the correct tarball URL for both namespaced and non-namespaced packages
func makeNpmTarballURL(pkg, version string) string {
	// If the package is namespaced (starts with "@"), we need to separate the namespace
	if strings.HasPrefix(pkg, "@") {
		// Extract the namespace and package name
		namespace := pkg[:strings.Index(pkg, "/")]
		packageName := pkg[strings.Index(pkg, "/")+1:]

		// Construct the URL for namespaced packages
		return fmt.Sprintf("https://registry.npmjs.org/%s/%s/-/%s-%s.tgz", namespace, packageName, packageName, version)
	} else {
		// For non-namespaced packages, the full name is used in both the path and tarball segment
		return fmt.Sprintf("https://registry.npmjs.org/%s/-/%s-%s.tgz", pkg, pkg, version)
	}
}

// Fetch package.json from an NPM package tarball, handling scoped packages correctly
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

	// Check for HTTP errors
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch package tarball: %s", resp.Status)
	}

	gzipReader, err := gzip.NewReader(resp.Body)
	if err != nil {
		return nil, err
	}
	tarReader := tar.NewReader(gzipReader)

	// Loop through files in the tarball to find the package.json
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		// Look for the package.json file inside the tarball
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

			// Return lifecycle scripts if any are found
			if len(lifecycleOnly) > 0 {
				return lifecycleOnly, nil
			}
		}
	}

	// If no lifecycle scripts found
	return nil, nil
}

// Parse dependencies from a package.json map
func parseDependencies(pkgData map[string]interface{}) []string {
	uniquePackages := make(map[string]bool)

	if dependencies, ok := pkgData["dependencies"].(map[string]interface{}); ok {
		for dep := range dependencies {
			uniquePackages[dep] = true
		}
	}
	if optionalDependencies, ok := pkgData["optionalDependencies"].(map[string]interface{}); ok {
		for dep := range optionalDependencies {
			uniquePackages[dep] = true
		}
	}

	var packages []string
	for pkg := range uniquePackages {
		packages = append(packages, pkg)
	}

	return packages
}

// Recursively process dependencies
func processPackage(pkg string, chain []string, depth int, wg *sync.WaitGroup, results chan<- PackageInfo) {
	defer wg.Done()

	version, err := getPackageMetadata(pkg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ Error fetching metadata for %s @ %s: %v\n", pkg, version, err)
		return
	}

	// Create a unique package identifier that includes the version
	pkgIdentifier := fmt.Sprintf("%s@%s", pkg, version)
	// Check if we've already processed this specific version
	if _, exists := processedPackages.Load(pkgIdentifier); exists {
		if verbose {
			fmt.Printf("📦 Skipping already processed package: %s\n", pkgIdentifier)
		}
		return
	}

	// Mark this specific version as processed
	processedPackages.Store(pkgIdentifier, true)

	scripts, err := getLifecycleScripts(pkg, version)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ Error fetching scripts for %s @ %s: %v\n", pkg, version, err)
		return
	}

	fullChain := append(chain, fmt.Sprintf("%s@%s", pkg, version))
	if scripts != nil {
		results <- PackageInfo{Name: pkg, Version: version, Scripts: scripts, Depth: depth, Chain: fullChain}
	}

	pkgData, err := fetchPackageJSON(pkg, version)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ Error fetching package.json for %s @ %s: %v\n", pkg, version, err)
		return
	}

	dependencies := parseDependencies(pkgData)
	fmt.Printf("✅ Processed %s @ %s\n", pkg, version)
	for _, dep := range dependencies {
		wg.Add(1)
		go processPackage(dep, fullChain, depth+1, wg, results)
	}
}

// Reads and parses the package.json file to get dependencies
func getDependenciesFromFile(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var pkgData map[string]interface{}
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&pkgData); err != nil {
		return nil, err
	}

	return parseDependencies(pkgData), nil
}

func main() {
	fmt.Println("🔍 NPM Script Hook Detection Tool")
	fmt.Println("Analyzing dependencies for potentially malicious lifecycle scripts...")
	fmt.Println()

	// Default to package.json in the current directory
	defaultPath := filepath.Join(".", "package.json")
	packageJSONPath := flag.String("package", defaultPath, "Path to package.json file")
	npmPackage := flag.String("npm", "", "NPM package to use as the starting point")
	verboseFlag := flag.Bool("verbose", false, "Enable verbose output")
	flag.Parse()

	verbose = *verboseFlag
	if verbose {
		fmt.Println("Verbose output enabled")
	}

	var packages []string
	var err error
	var rootChain []string

	if *npmPackage != "" {
		// Fetch dependencies from the specified NPM package
		version, err := getPackageMetadata(*npmPackage)
		if err != nil {
			fmt.Fprintf(os.Stderr, "❌ Error fetching metadata for %s: %v\n", *npmPackage, err)
			os.Exit(1)
		}

		pkgData, err := fetchPackageJSON(*npmPackage, version)
		if err != nil {
			fmt.Fprintf(os.Stderr, "❌ Error fetching package.json for %s: %v\n", *npmPackage, err)
			os.Exit(1)
		}

		packages = parseDependencies(pkgData)
		rootChain = []string{fmt.Sprintf("%s@%s", *npmPackage, version)}
	} else {
		// Read dependencies from a local package.json
		packages, err = getDependenciesFromFile(*packageJSONPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "❌ Error reading dependencies: %v\n", err)
			os.Exit(1)
		}

		rootChain = []string{"local-package"}
	}

	var wg sync.WaitGroup
	results := make(chan PackageInfo, len(packages))

	for _, pkg := range packages {
		wg.Add(1)
		go processPackage(pkg, rootChain, 1, &wg, results)
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
