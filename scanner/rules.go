package scanner

type Rule struct {
	ID          string
	Name        string
	Language    string
	Pattern     string // Regex pattern
	Severity    string
	Description string
}

// GetDefaultRules returns the list of vulnerability signatures
func GetDefaultRules() []Rule {
	return []Rule{
		// PYTHON
		{
			ID:          "PY-PICKLE",
			Name:        "Python Pickle Deserialization",
			Language:    "Python",
			Pattern:     `pickle\.load\s*\(|cPickle\.load\s*\(`,
			Severity:    "CRITICAL",
			Description: "Detected usage of pickle.load(). This function is insecure and can lead to RCE.",
		},
		{
			ID:          "PY-YAML",
			Name:        "Python PyYAML Unsafe Load",
			Language:    "Python",
			Pattern:     `yaml\.load\s*\(`,
			Severity:    "HIGH",
			Description: "yaml.load() is unsafe by default. Use yaml.safe_load() instead.",
		},
		// JAVA
		{
			ID:          "JAVA-OBJ-STREAM",
			Name:        "Java ObjectInputStream",
			Language:    "Java",
			Pattern:     `readObject\s*\(`,
			Severity:    "MEDIUM",
			Description: "Usage of readObject() detected. Ensure appropriate security checks or lookahead validation.",
		},
		{
			ID:          "JAVA-XML-DECODER",
			Name:        "Java XMLDecoder",
			Language:    "Java",
			Pattern:     `new\s+XMLDecoder\s*\(`,
			Severity:    "HIGH",
			Description: "XMLDecoder is vulnerable to RCE if used with untrusted data.",
		},
		// PHP
		{
			ID:          "PHP-UNSERIALIZE",
			Name:        "PHP Unserialize",
			Language:    "PHP",
			Pattern:     `unserialize\s*\(`,
			Severity:    "CRITICAL",
			Description: "unserialize() on user input leads to Object Injection vulnerabilities.",
		},
		// NODE.JS
		{
			ID:          "NODE-SERIALIZE",
			Name:        "Node.js node-serialize",
			Language:    "JavaScript",
			Pattern:     `unserialize\s*\(`,
			Severity:    "HIGH",
			Description: "node-serialize library is known to be vulnerable to RCE via IIFE.",
		},
	}
}
