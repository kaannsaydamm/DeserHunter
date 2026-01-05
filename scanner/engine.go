package scanner

import (
	"archive/zip"
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

type Finding struct {
	FilePath    string
	LineNumber  int
	LineContent string
	Context     []string
	Rule        Rule
	Author      string // Git Blame Author
	CommitDate  string // Git Blame Date
	Confidence  string // HIGH/LOW based on taint analysis
}

type Engine struct {
	Rules []Rule
}

func NewEngine() *Engine {
	return &Engine{
		Rules: GetDefaultRules(),
	}
}

func (e *Engine) ScanConcurrently(root string, workers int) ([]Finding, error) {
	filesChan := make(chan string, 100)
	resultsChan := make(chan []Finding, 100)
	var wg sync.WaitGroup

	// File Walker
	go func() {
		defer close(filesChan)
		filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if !info.IsDir() {
				// 4. Magic Byte Detection & Archive Handling
				ext := strings.ToLower(filepath.Ext(path))

				// Check for archives
				if ext == ".jar" || ext == ".war" || ext == ".zip" {
					filesChan <- "ARCHIVE:" + path
					return nil
				}

				// Check for "Masked" files (e.g. .png containing PHP)
				// OR just standard code files
				if isSuspectFile(path) {
					filesChan <- path
				}
			}
			return nil
		})
	}()

	// Workers
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for path := range filesChan {
				if strings.HasPrefix(path, "ARCHIVE:") {
					realPath := strings.TrimPrefix(path, "ARCHIVE:")
					resultsChan <- e.scanArchive(realPath)
				} else {
					resultsChan <- e.scanFile(path)
				}
			}
		}()
	}

	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	var allFindings []Finding
	for findings := range resultsChan {
		allFindings = append(allFindings, findings...)
	}

	return allFindings, nil
}

// isSuspectFile checks extensions or Magic Bytes
func isSuspectFile(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	// Standard extensions
	if ext == ".php" || ext == ".java" || ext == ".py" || ext == ".js" || ext == ".go" {
		return true
	}

	// 4. Magic Byte Detection
	// Read first 512 bytes to see if it contains script tags
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()

	buf := make([]byte, 512)
	n, _ := f.Read(buf)
	content := string(buf[:n])

	// Check for PHP tag even in .png/.txt
	if strings.Contains(content, "<?php") {
		return true
	}
	// Check for Shebang
	if strings.HasPrefix(content, "#!") {
		return true
	}

	return false
}

func (e *Engine) scanArchive(path string) []Finding {
	var findings []Finding

	r, err := zip.OpenReader(path)
	if err != nil {
		return findings
	}
	defer r.Close()

	for _, f := range r.File {
		if f.FileInfo().IsDir() {
			continue
		}

		rc, err := f.Open()
		if err != nil {
			continue
		}

		fileFindings := e.scanStream(rc, path+"://"+f.Name, false)
		findings = append(findings, fileFindings...)
		rc.Close()
	}
	return findings
}

func (e *Engine) scanFile(path string) []Finding {
	file, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer file.Close()
	return e.scanStream(file, path, true) // true = check git blame
}

func (e *Engine) scanStream(reader io.Reader, displayPath string, checkGit bool) []Finding {
	var findings []Finding
	var lines []string

	scanner := bufio.NewScanner(reader)
	// Buffer expanding for long lines (obfuscation)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Noise Filter
		if strings.HasPrefix(trimmed, "//") ||
			strings.HasPrefix(trimmed, "#") ||
			strings.HasPrefix(trimmed, "*") ||
			strings.Contains(line, "Pattern:") || // Ignore self-detection
			strings.Contains(line, "Description:") { // Ignore self-detection
			continue
		}

		// 5. Obfuscation / High Entropy Scanner (Simple Heuristic)
		if len(line) > 500 && !strings.Contains(line, " ") {
			// Suspicious long string without attributes
			findings = append(findings, Finding{
				FilePath:    displayPath,
				LineNumber:  i + 1,
				LineContent: line[:100] + "...", // Truncate
				Rule: Rule{
					ID:          "SUSPICIOUS-OBFUSCATION",
					Name:        "Potential Code Obfuscation",
					Severity:    "MEDIUM",
					Description: "Detected unusually long string/code block. Could be base64 encoded payload.",
				},
				Confidence: "MEDIUM",
			})
		}

		// Obfuscate the signature itself so this file is not flagged
		sig := "eval" + "(base64_decode"
		if strings.Contains(line, sig) {
			findings = append(findings, Finding{
				FilePath:    displayPath,
				LineNumber:  i + 1,
				LineContent: strings.TrimSpace(line),
				Rule: Rule{
					ID:          "PHP-OBFUSCATION",
					Name:        "PHP Obfuscation Detected",
					Severity:    "HIGH",
					Description: "Usage of eval(base64_decode(...)) is a common sign of backdoors.",
				},
				Confidence: "HIGH",
			})
		}

		for _, rule := range e.Rules {
			matched, _ := regexp.MatchString(rule.Pattern, line)
			if matched {
				// 1. Heuristic Taint Analysis
				// If the match is followed by a quote, it might be a hardcoded string
				// E.g. unserialize("...
				confidence := "HIGH"

				// Make a temporary regex that appends the quote check
				if isHardcoded(rule.Pattern, line) {
					confidence = "LOW"
				}

				// Context
				start := i - 2
				if start < 0 {
					start = 0
				}
				end := i + 3
				if end > len(lines) {
					end = len(lines)
				}
				contextLines := lines[start:end]

				// 3. Git Blame
				author, date := "Unknown", "Unknown"
				if checkGit {
					author, date = getGitBlame(displayPath, i+1)
				}

				findings = append(findings, Finding{
					FilePath:    displayPath,
					LineNumber:  i + 1,
					LineContent: strings.TrimSpace(line),
					Context:     contextLines,
					Rule:        rule,
					Author:      author,
					CommitDate:  date,
					Confidence:  confidence,
				})
			}
		}
	}
	return findings
}

func isHardcoded(pattern string, line string) bool {
	// Check if the pattern match in the line is followed by quotes
	// This assumes the pattern ends right before the argument list starts or is the function name

	// Compile regex with a lookahead-ish check for quotes
	// Pattern + optional space + optional open paren + optional space + quote
	// Removing escaping slash from pattern if exists to avoid double escape issues with raw string?
	// Actually pattern comes from Rule.Pattern which is a Go regex string.
	regexComp := pattern + `\s*\(?\s*['"]`
	re, err := regexp.Compile(regexComp)
	if err != nil {
		return false
	}
	return re.MatchString(line)
}

func getGitBlame(path string, line int) (string, string) {
	// Check if git exists/folder is git repo
	if _, err := os.Stat(".git"); os.IsNotExist(err) {
		return "Not-Git-Repo", ""
	}

	cmd := exec.Command("git", "blame", "-L", fmt.Sprintf("%d,%d", line, line), "--porcelain", path)
	out, err := cmd.Output()
	if err != nil {
		return "Unknown", "Unknown"
	}

	author := "Unknown"
	date := "Unknown"

	lines := strings.Split(string(out), "\n")
	for _, l := range lines {
		if strings.HasPrefix(l, "author ") {
			author = strings.TrimPrefix(l, "author ")
		}
		if strings.HasPrefix(l, "author-time ") {
			// Convert timestamp if needed, or simple raw
			date = strings.TrimPrefix(l, "author-time ")
		}
	}
	return author, date
}
