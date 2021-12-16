package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/hillu/local-log4j-vuln-scanner/filter"
)

type excludeFlags []string

var (
	verbose     bool
	apiUrl      string
	excludes    excludeFlags
	ignoreV1    bool
	quiet       bool
	logFileName string
	vulnFiles   []string
	hostname, _ = os.Hostname()
	logFile     = os.Stdout
	errFile     = os.Stderr
)

func (flags *excludeFlags) String() string {
	return fmt.Sprint(*flags)
}

func (flags *excludeFlags) Set(value string) error {
	*flags = append(*flags, value)
	return nil
}

func (flags excludeFlags) Has(path string) bool {
	for _, exclude := range flags {
		if path == exclude {
			return true
		}
	}
	return false
}

func handleJar(path string, ra io.ReaderAt, sz int64) {
	// Get absolute path to jar file
	absPath, err := filepath.Abs(path)
	if err != nil {
		fmt.Fprintf(errFile, "Could not get absolute path to %s: %s\n", path, err)
		absPath = path
	}
	if verbose {
		fmt.Fprintf(logFile, "Inspecting %s...\n", absPath)
	}
	zr, err := zip.NewReader(ra, sz)
	if err != nil {
		fmt.Fprintf(logFile, "cant't open JAR file: %s (size %d): %v\n", absPath, sz, err)
		return
	}
	for _, file := range zr.File {
		switch strings.ToLower(filepath.Ext(file.Name)) {
		case ".class":
			fr, err := file.Open()
			if err != nil {
				fmt.Fprintf(logFile, "can't open JAR file member for reading: %s (%s): %v\n", absPath, file.Name, err)
				continue
			}
			buf := bytes.NewBuffer(nil)
			if _, err = io.Copy(buf, fr); err != nil {
				fmt.Fprintf(logFile, "can't read JAR file member: %s (%s): %v\n", absPath, file.Name, err)
				fr.Close()
				continue
			}
			fr.Close()
			if desc := filter.IsVulnerableClass(buf.Bytes(), file.Name, !ignoreV1); desc != "" {
				// fmt.Fprintf(logFile, "indicator for vulnerable component found in %s (%s): %s\n", path, file.Name, desc)

				// Make a POST the data to the API
				vulnFiles = append(vulnFiles, absPath)
				continue
			}

		case ".jar", ".war", ".ear":
			fr, err := file.Open()
			if err != nil {
				fmt.Fprintf(logFile, "can't open JAR file member for reading: %s (%s): %v\n", absPath, file.Name, err)
				continue
			}
			buf, err := ioutil.ReadAll(fr)
			fr.Close()
			if err != nil {
				fmt.Fprintf(logFile, "can't read JAR file member: %s (%s): %v\n", absPath, file.Name, err)
			}
			handleJar(path+"::"+file.Name, bytes.NewReader(buf), int64(len(buf)))
		}
	}
}

func init() {

	flag.Var(&excludes, "exclude", "paths to exclude")
	flag.StringVar(&apiUrl, "api", "", "API URL")
	flag.BoolVar(&verbose, "verbose", false, "log every archive file considered")
	flag.StringVar(&logFileName, "log", "", "log file to write output to")
	flag.BoolVar(&quiet, "quiet", false, "no ouput unless vulnerable")
	flag.BoolVar(&ignoreV1, "ignore-v1", false, "ignore log4j 1.x versions")
	flag.Parse()

	if !quiet {
		fmt.Printf("%s - a simple local log4j vulnerability scanner based on github.com/hillu/local-log4j-vuln-scanner\n", filepath.Base(os.Args[0]))
	}

	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s [--api] [--verbose] [--quiet] [--ignore-v1] [--log logfilename] [--exclude path] [ paths ... ]\n", os.Args[0])
		os.Exit(1)
	}

	if logFileName != "" {
		f, err := os.Create(logFileName)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Could not create log file")
			os.Exit(2)
		}
		logFile = f
		errFile = f
		defer f.Close()
	}
}

func main() {

	// Recoursively scan all the files in the given path
	for _, root := range flag.Args() {
		filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				fmt.Fprintf(errFile, "%s: %s\n", path, err)
				return nil
			}
			if excludes.Has(path) {
				return filepath.SkipDir
			}
			if info.IsDir() {
				return nil
			}
			switch ext := strings.ToLower(filepath.Ext(path)); ext {
			case ".jar", ".war", ".ear":
				f, err := os.Open(path)
				if err != nil {
					fmt.Fprintf(errFile, "can't open %s: %v\n", path, err)
					return nil
				}
				defer f.Close()
				sz, err := f.Seek(0, os.SEEK_END)
				if err != nil {
					fmt.Fprintf(errFile, "can't seek in %s: %v\n", path, err)
					return nil
				}
				if _, err := f.Seek(0, os.SEEK_END); err != nil {
					fmt.Fprintf(errFile, "can't seek in %s: %v\n", path, err)
					return nil
				}
				handleJar(path, f, sz)
			default:
				return nil
			}
			return nil
		})
	}

	if !quiet {
		fmt.Println("\nScan finished")
		// Print the vulnFiles
		if len(vulnFiles) > 0 {
			fmt.Println("\nVulnerable files:")
			for _, f := range vulnFiles {
				fmt.Println(f)
			}
		} else {
			fmt.Println("No vulnerable files found")
		}
	}

	if apiUrl != "" {
		// Parse the data to json API request
		var mapSlice []map[string]string
		for _, f := range vulnFiles {
			mapSlice = append(mapSlice, map[string]string{"fileName": f})
		}

		// var jsonMap = map[string]interface{}{"servername": "hostname", "vulnerableFiles": mapSlice}
		jsonMap := map[string]interface{}{"servername": hostname, "vulnerableFiles": mapSlice}

		// Convert jsonMap2 to bytes
		jsonBytes, err := json.Marshal(jsonMap)
		if err != nil {
			fmt.Fprintf(errFile, "Error in marshalling jsonMap2: %v\n", err)
			return
		}

		// Post the data to the apiUrl
		req, err := http.NewRequest("POST", apiUrl, bytes.NewBuffer(jsonBytes))
		if err != nil {
			fmt.Fprintf(errFile, "Error creating request: %v\n", err)
			return
		}
		req.Header.Set("Content-Type", "application/json")

		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			fmt.Fprintf(errFile, "Error posting data: %v\n", err)
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			fmt.Fprintf(errFile, "Error posting data: %v\n", err)
			return
		}

		fmt.Printf("\nData successfully posted to %s\n", apiUrl)

	}
}
