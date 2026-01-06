package explain

// CWEInfo contains human-readable information about a CWE.
type CWEInfo struct {
	ID          string
	Name        string
	Description string
	Category    string
}

// GetCWEInfo returns human-readable information for common CWEs.
// For unknown CWEs, returns basic info with the ID.
func GetCWEInfo(cweID string) CWEInfo {
	if info, ok := cweDatabase[cweID]; ok {
		return info
	}
	return CWEInfo{
		ID:          cweID,
		Name:        "Unknown Weakness",
		Description: "See https://cwe.mitre.org for details",
		Category:    "Other",
	}
}

// cweDatabase contains human-readable descriptions for common CWEs.
// This covers the OWASP Top 10 and frequently seen weaknesses.
var cweDatabase = map[string]CWEInfo{
	// Injection flaws
	"CWE-74": {
		ID:          "CWE-74",
		Name:        "Improper Neutralization of Special Elements",
		Description: "The application does not properly neutralize special elements that could modify the intended behavior of a downstream component.",
		Category:    "Injection",
	},
	"CWE-78": {
		ID:          "CWE-78",
		Name:        "OS Command Injection",
		Description: "The application constructs OS commands using externally-influenced input without proper sanitization, allowing attackers to execute arbitrary commands.",
		Category:    "Injection",
	},
	"CWE-89": {
		ID:          "CWE-89",
		Name:        "SQL Injection",
		Description: "The application constructs SQL queries using user input without proper sanitization, allowing attackers to manipulate database queries.",
		Category:    "Injection",
	},
	"CWE-94": {
		ID:          "CWE-94",
		Name:        "Code Injection",
		Description: "The application allows user input to be executed as code, enabling attackers to run arbitrary code within the application context.",
		Category:    "Injection",
	},
	"CWE-917": {
		ID:          "CWE-917",
		Name:        "Expression Language Injection",
		Description: "The application evaluates user input as expression language without sanitization, allowing code execution.",
		Category:    "Injection",
	},

	// Cross-Site Scripting
	"CWE-79": {
		ID:          "CWE-79",
		Name:        "Cross-site Scripting (XSS)",
		Description: "The application includes user-supplied data in web pages without proper validation, allowing attackers to inject malicious scripts.",
		Category:    "XSS",
	},

	// Memory Safety
	"CWE-120": {
		ID:          "CWE-120",
		Name:        "Buffer Copy without Size Checking",
		Description: "The application copies data to a buffer without checking size, potentially causing buffer overflow and code execution.",
		Category:    "Memory Safety",
	},
	"CWE-125": {
		ID:          "CWE-125",
		Name:        "Out-of-bounds Read",
		Description: "The application reads data past the end of a buffer, potentially leaking sensitive information.",
		Category:    "Memory Safety",
	},
	"CWE-787": {
		ID:          "CWE-787",
		Name:        "Out-of-bounds Write",
		Description: "The application writes data past the end of a buffer, potentially corrupting memory or enabling code execution.",
		Category:    "Memory Safety",
	},
	"CWE-416": {
		ID:          "CWE-416",
		Name:        "Use After Free",
		Description: "The application references memory after it has been freed, leading to undefined behavior or code execution.",
		Category:    "Memory Safety",
	},
	"CWE-476": {
		ID:          "CWE-476",
		Name:        "NULL Pointer Dereference",
		Description: "The application dereferences a null pointer, causing crashes or potentially exploitable conditions.",
		Category:    "Memory Safety",
	},
	"CWE-190": {
		ID:          "CWE-190",
		Name:        "Integer Overflow",
		Description: "An arithmetic operation results in an integer overflow, potentially leading to buffer overflows or logic errors.",
		Category:    "Memory Safety",
	},

	// Authentication/Authorization
	"CWE-287": {
		ID:          "CWE-287",
		Name:        "Improper Authentication",
		Description: "The application does not properly verify the identity of users, allowing unauthorized access.",
		Category:    "Authentication",
	},
	"CWE-862": {
		ID:          "CWE-862",
		Name:        "Missing Authorization",
		Description: "The application does not perform authorization checks, allowing users to access resources beyond their privileges.",
		Category:    "Authorization",
	},
	"CWE-863": {
		ID:          "CWE-863",
		Name:        "Incorrect Authorization",
		Description: "The application performs authorization incorrectly, potentially granting access to unauthorized users.",
		Category:    "Authorization",
	},
	"CWE-269": {
		ID:          "CWE-269",
		Name:        "Improper Privilege Management",
		Description: "The application does not properly manage privileges, allowing privilege escalation.",
		Category:    "Authorization",
	},
	"CWE-798": {
		ID:          "CWE-798",
		Name:        "Use of Hard-coded Credentials",
		Description: "The application contains hard-coded credentials that can be discovered and used by attackers.",
		Category:    "Authentication",
	},

	// Cryptographic Issues
	"CWE-327": {
		ID:          "CWE-327",
		Name:        "Use of Broken Cryptographic Algorithm",
		Description: "The application uses a cryptographic algorithm that is known to be weak or broken.",
		Category:    "Cryptography",
	},
	"CWE-311": {
		ID:          "CWE-311",
		Name:        "Missing Encryption of Sensitive Data",
		Description: "Sensitive data is transmitted or stored without encryption, allowing interception.",
		Category:    "Cryptography",
	},
	"CWE-295": {
		ID:          "CWE-295",
		Name:        "Improper Certificate Validation",
		Description: "The application does not properly validate certificates, enabling man-in-the-middle attacks.",
		Category:    "Cryptography",
	},

	// Path Traversal
	"CWE-22": {
		ID:          "CWE-22",
		Name:        "Path Traversal",
		Description: "The application uses user input to construct file paths without proper validation, allowing access to arbitrary files.",
		Category:    "Path Traversal",
	},
	"CWE-434": {
		ID:          "CWE-434",
		Name:        "Unrestricted File Upload",
		Description: "The application allows uploading files without proper validation, potentially enabling code execution.",
		Category:    "Path Traversal",
	},

	// Deserialization
	"CWE-502": {
		ID:          "CWE-502",
		Name:        "Deserialization of Untrusted Data",
		Description: "The application deserializes data from untrusted sources, potentially allowing arbitrary code execution.",
		Category:    "Deserialization",
	},

	// Information Disclosure
	"CWE-200": {
		ID:          "CWE-200",
		Name:        "Exposure of Sensitive Information",
		Description: "The application unintentionally exposes sensitive information to unauthorized actors.",
		Category:    "Information Disclosure",
	},
	"CWE-209": {
		ID:          "CWE-209",
		Name:        "Information Exposure Through Error Messages",
		Description: "Error messages reveal sensitive implementation details that aid attackers.",
		Category:    "Information Disclosure",
	},

	// Denial of Service
	"CWE-400": {
		ID:          "CWE-400",
		Name:        "Uncontrolled Resource Consumption",
		Description: "The application does not limit resource usage, allowing denial-of-service attacks.",
		Category:    "Denial of Service",
	},
	"CWE-1333": {
		ID:          "CWE-1333",
		Name:        "Inefficient Regular Expression",
		Description: "A regular expression is vulnerable to catastrophic backtracking (ReDoS).",
		Category:    "Denial of Service",
	},

	// Request Forgery
	"CWE-918": {
		ID:          "CWE-918",
		Name:        "Server-Side Request Forgery (SSRF)",
		Description: "The application makes server-side requests to URLs controlled by attackers.",
		Category:    "Request Forgery",
	},
	"CWE-352": {
		ID:          "CWE-352",
		Name:        "Cross-Site Request Forgery (CSRF)",
		Description: "The application allows attackers to trick users into performing unintended actions.",
		Category:    "Request Forgery",
	},

	// XML
	"CWE-611": {
		ID:          "CWE-611",
		Name:        "XML External Entity (XXE)",
		Description: "The XML parser processes external entity references, allowing file disclosure or SSRF.",
		Category:    "XML",
	},

	// Other common ones
	"CWE-20": {
		ID:          "CWE-20",
		Name:        "Improper Input Validation",
		Description: "The application does not properly validate input, leading to various vulnerabilities.",
		Category:    "Input Validation",
	},
	"CWE-77": {
		ID:          "CWE-77",
		Name:        "Command Injection",
		Description: "The application passes user input to a command interpreter without sanitization.",
		Category:    "Injection",
	},
	"CWE-119": {
		ID:          "CWE-119",
		Name:        "Memory Buffer Boundary Violation",
		Description: "The application performs operations on a memory buffer without proper bounds checking.",
		Category:    "Memory Safety",
	},
	"CWE-362": {
		ID:          "CWE-362",
		Name:        "Race Condition",
		Description: "The application has concurrent access to shared resources without proper synchronization.",
		Category:    "Concurrency",
	},
	"CWE-601": {
		ID:          "CWE-601",
		Name:        "URL Redirection to Untrusted Site",
		Description: "The application redirects users to URLs controlled by attackers (open redirect).",
		Category:    "Redirection",
	},
	"CWE-732": {
		ID:          "CWE-732",
		Name:        "Incorrect Permission Assignment",
		Description: "The application assigns incorrect permissions to resources.",
		Category:    "Authorization",
	},

	// Container/File descriptor related
	"CWE-403": {
		ID:          "CWE-403",
		Name:        "Exposure of File Descriptor to Unintended Control Sphere",
		Description: "A file descriptor is exposed to code outside the intended control boundary, potentially allowing unauthorized access.",
		Category:    "File Handling",
	},
	"CWE-668": {
		ID:          "CWE-668",
		Name:        "Exposure of Resource to Wrong Sphere",
		Description: "The application exposes a resource to the wrong control sphere, allowing unauthorized access or manipulation.",
		Category:    "Access Control",
	},

	// Prototype pollution / property injection
	"CWE-1321": {
		ID:          "CWE-1321",
		Name:        "Improperly Controlled Modification of Object Prototype Attributes",
		Description: "The application allows modification of object prototype attributes (prototype pollution).",
		Category:    "Injection",
	},

	// Additional common CWEs
	"CWE-770": {
		ID:          "CWE-770",
		Name:        "Allocation of Resources Without Limits",
		Description: "The application allocates reusable resources without imposing limits, enabling resource exhaustion.",
		Category:    "Denial of Service",
	},
	"CWE-306": {
		ID:          "CWE-306",
		Name:        "Missing Authentication for Critical Function",
		Description: "The application does not require authentication for critical functionality.",
		Category:    "Authentication",
	},

	// Logic/Implementation errors
	"CWE-670": {
		ID:          "CWE-670",
		Name:        "Always-Incorrect Control Flow Implementation",
		Description: "The code contains control flow that does not properly accomplish its intended purpose.",
		Category:    "Logic Error",
	},
	"CWE-754": {
		ID:          "CWE-754",
		Name:        "Improper Check for Unusual or Exceptional Conditions",
		Description: "The application does not properly check for unusual conditions that rarely occur.",
		Category:    "Error Handling",
	},
	"CWE-755": {
		ID:          "CWE-755",
		Name:        "Improper Handling of Exceptional Conditions",
		Description: "The application does not properly handle exceptional conditions.",
		Category:    "Error Handling",
	},
	"CWE-834": {
		ID:          "CWE-834",
		Name:        "Excessive Iteration",
		Description: "The application performs an iteration without properly limiting the number of times the loop is executed.",
		Category:    "Denial of Service",
	},
}
