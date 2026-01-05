package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/kaannsaydamm/deserhunter/scanner"
)

// ANSI Colors
const (
	ColorReset   = "\033[0m"
	ColorRed     = "\033[31m"
	ColorGreen   = "\033[32m"
	ColorYellow  = "\033[33m"
	ColorCyan    = "\033[36m"
	ColorBlue    = "\033[34m"
	ColorMagenta = "\033[35m"
	ColorWhite   = "\033[37m"
)

func banner() {
	fmt.Println(ColorMagenta + `
    ____                      __  __            __               
   / __ \___  ________  _____/ / / /_  ______  / /____  _____    
  / / / / _ \/ ___/ _ \/ ___/ /_/ / / / / __ \/ __/ _ \/ ___/    
 / /_/ /  __(__  )  __/ /  / __  / /_/ / / / / /_/  __/ /        
/_____/\___/____/\___/_/  /_/ /_/\__,_/_/ /_/\__/\___/_/         

                                        By Kaan Saydam     
` + ColorReset)
}

func main() {
	// Custom usage message
	flag.Usage = func() {
		banner()
		fmt.Fprintf(os.Stderr, "Usage: %s [options]\n\n", os.Args[0])
		fmt.Println("Options:")
		flag.PrintDefaults()
		fmt.Println("\nExamples:")
		fmt.Printf("  %s --wizard\n", os.Args[0])
		fmt.Printf("  %s --target /var/www/html --format json\n", os.Args[0])
	}

	targetDir := flag.String("target", "", "Directory to scan")
	outputFormat := flag.String("format", "text", "Output format (text/json/sarif)")
	workers := flag.Int("workers", 50, "Number of concurrent workers")
	wizard := flag.Bool("wizard", false, "Run in interactive wizard mode")
	verbose := flag.Bool("verbose", false, "Enable verbose logging")

	flag.Parse()

	// If no args provided or wizard flag set, run wizard
	if len(os.Args) == 1 || *wizard {
		runWizard(targetDir, outputFormat, workers, verbose)
	}

	if *targetDir == "" {
		fmt.Println(ColorRed + "Error: Target directory is required." + ColorReset)
		flag.Usage()
		os.Exit(1)
	}

	if *outputFormat == "text" {
		banner()
		fmt.Printf("[*] Target: %s\n", *targetDir)
		fmt.Printf("[*] Workers: %d\n", *workers)
		if *verbose {
			fmt.Println("[*] Verbose mode: Enabled")
		}
		fmt.Println("[*] Scanning started...")
	}

	startTime := time.Now()

	engine := scanner.NewEngine()
	// Pass verbose flag to engine if needed, or just use it here
	findings, err := engine.ScanConcurrently(*targetDir, *workers)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	duration := time.Since(startTime)

	switch *outputFormat {
	case "json":
		outputJSON(findings)
	case "sarif":
		outputSARIF(findings)
	default:
		outputText(findings)
		fmt.Printf("\n[+] Scan completed in %s\n", duration)
		if *verbose {
			fmt.Printf("[+] Total files scanned: (dynamic)\n")
		}
		fmt.Printf("[!] Issues found: %d\n", len(findings))
	}
}

func runWizard(target *string, format *string, workers *int, verbose *bool) {
	banner()
	fmt.Println(ColorCyan + "Welcome to DeserHunter Interactive Wizard" + ColorReset)
	fmt.Println("-----------------------------------------")

	reader := bufio.NewScanner(os.Stdin)

	// 1. Target Directory
	fmt.Print(ColorGreen + "[?] Enter directory to scan (default: .): " + ColorReset)
	reader.Scan()
	input := strings.TrimSpace(reader.Text())
	if input == "" {
		*target = "."
	} else {
		*target = input
	}

	// 2. Output Format
	fmt.Print(ColorGreen + "[?] Output format [text/json/sarif] (default: text): " + ColorReset)
	reader.Scan()
	input = strings.TrimSpace(reader.Text())
	if input == "" {
		*format = "text"
	} else {
		*format = strings.ToLower(input)
	}

	// 3. Workers
	fmt.Print(ColorGreen + "[?] Number of workers (default: 50): " + ColorReset)
	reader.Scan()
	input = strings.TrimSpace(reader.Text())
	if input == "" {
		*workers = 50
	} else {
		val, err := strconv.Atoi(input)
		if err == nil && val > 0 {
			*workers = val
		}
	}

	// 4. Verbose
	fmt.Print(ColorGreen + "[?] Enable verbose mode? [y/N]: " + ColorReset)
	reader.Scan()
	input = strings.TrimSpace(reader.Text())
	if strings.ToLower(input) == "y" || strings.ToLower(input) == "yes" {
		*verbose = true
	} else {
		*verbose = false
	}

	fmt.Println("-----------------------------------------")
	fmt.Println(ColorYellow + "Starting scan with selected parameters..." + ColorReset)
	time.Sleep(1 * time.Second) // Small UX pause
}

func outputText(findings []scanner.Finding) {
	for _, f := range findings {
		color := ColorReset
		switch f.Rule.Severity {
		case "CRITICAL", "HIGH":
			color = ColorRed
		case "MEDIUM":
			color = ColorYellow
		}

		// Dim color for low confidence
		if f.Confidence == "LOW" {
			color = ColorBlue
		}

		fmt.Printf("\n%s[%s] %s (Confidence: %s)%s\n", color, f.Rule.Severity, f.Rule.Name, f.Confidence, ColorReset)
		fmt.Printf("  File: %s:%d\n", f.FilePath, f.LineNumber)
		if f.Author != "Unknown" {
			fmt.Printf("  Blame: %s (%s)\n", f.Author, f.CommitDate)
		}

		// Context Yazdırma
		fmt.Println("  Context:")
		for _, ctxLine := range f.Context {
			if strings.Contains(ctxLine, f.LineContent) {
				// Bulunan satırı vurgula
				fmt.Printf("    %s> %s%s\n", ColorRed, strings.TrimSpace(ctxLine), ColorReset)
			} else {
				fmt.Printf("      %s\n", strings.TrimSpace(ctxLine))
			}
		}
		fmt.Printf("  Desc: %s\n", f.Rule.Description)
	}
}

func outputJSON(findings []scanner.Finding) {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	encoder.Encode(findings)
}

// SARIF Structure definitions
type SarifRun struct {
	Tool    SarifTool     `json:"tool"`
	Results []SarifResult `json:"results"`
}
type SarifTool struct {
	Driver SarifDriver `json:"driver"`
}
type SarifDriver struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}
type SarifResult struct {
	RuleId    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   SarifMessage    `json:"message"`
	Locations []SarifLocation `json:"locations"`
}
type SarifMessage struct {
	Text string `json:"text"`
}
type SarifLocation struct {
	PhysicalLocation SarifPhysicalLocation `json:"physicalLocation"`
}
type SarifPhysicalLocation struct {
	ArtifactLocation SarifArtifactLocation `json:"artifactLocation"`
	Region           SarifRegion           `json:"region"`
}
type SarifArtifactLocation struct {
	Uri string `json:"uri"`
}
type SarifRegion struct {
	StartLine int `json:"startLine"`
}

func outputSARIF(findings []scanner.Finding) {
	run := SarifRun{
		Tool: SarifTool{
			Driver: SarifDriver{
				Name:    "DeserHunter",
				Version: "1.0.0",
			},
		},
		Results: []SarifResult{},
	}

	for _, f := range findings {
		level := "warning"
		if f.Rule.Severity == "CRITICAL" || f.Rule.Severity == "HIGH" {
			level = "error"
		}

		run.Results = append(run.Results, SarifResult{
			RuleId: f.Rule.ID,
			Level:  level,
			Message: SarifMessage{
				Text: fmt.Sprintf("%s. %s", f.Rule.Name, f.Rule.Description),
			},
			Locations: []SarifLocation{
				{
					PhysicalLocation: SarifPhysicalLocation{
						ArtifactLocation: SarifArtifactLocation{Uri: f.FilePath},
						Region:           SarifRegion{StartLine: f.LineNumber},
					},
				},
			},
		})
	}

	output := map[string]interface{}{
		"version": "2.1.0",
		"$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		"runs":    []SarifRun{run},
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	encoder.Encode(output)
}
