package csaf

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// CSAF is a Common Security Advisory Framework Version 2.0 document.
//
// https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html
type CSAF struct {
	// Document contains metadata about the CSAF document itself.
	//
	// https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#321-document-property
	Document DocumentMetadata `json:"document"`

	// ProductTree contains information about the product tree (branches only).
	//
	// https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#322-product-tree-property
	ProductTree ProductBranch `json:"product_tree"`

	// Vulnerabilities contains information about the vulnerabilities,
	// (i.e. CVEs), associated threats, and product status.
	//
	// https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#323-vulnerabilities-property
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

// DocumentMetadata contains metadata about the CSAF document itself.
//
// https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#321-document-property
type DocumentMetadata struct {
	// Aggregate severity is a vehicle that is provided by the document producer to convey the urgency and
	// criticality with which the one or more vulnerabilities reported should be addressed.
	//
	// https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#3212-document-property---aggregate-severity
	AggregateSeverity Severity `json:"aggregate_severity"`
	// https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#3213-document-property---category
	Category   string      `json:"category"`
	Notes      []Note      `json:"notes"`
	Title      string      `json:"title"`
	Tracking   Tracking    `json:"tracking"`
	References []Reference `json:"references"`
}

// Note with the mandatory properties category and text providing a place to put all manner of text blobs related to the current context.
//
// https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#315-notes-type
type Note struct {
	Category string `json:"category"`
	Text     string `json:"text"`
	Title    string `json:"title,omitempty"`
}

// Document references holds a list of references associated with the whole document.
//
// https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#3219-document-property---references
type Reference struct {
	Category string `json:"category"`
	Summary  string `json:"summary"`
	URL      string `json:"url"`
}

// Severity with the mandatory property text and the optional property namespace is a vehicle that is provided by the document producer to convey the urgency and criticality with which the one or more vulnerabilities reported should be addressed.
//
// https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#3212-document-property---aggregate-severity
type Severity struct {
	Namespace string `json:"namespace,omitempty"`
	Text      string `json:"text"`
}

// Tracking contains information used to track the CSAF document through its lifecycle.
//
// https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#32112-document-property---tracking
type Tracking struct {
	ID                 string    `json:"id"`
	CurrentReleaseDate time.Time `json:"current_release_date"`
	InitialReleaseDate time.Time `json:"initial_release_date"`
}

// Vulnerability contains information about a CVE and its associated threats.
//
// https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#323-vulnerabilities-property
type Vulnerability struct {
	// MITRE standard Common Vulnerabilities and Exposures (CVE) tracking number for the vulnerability.
	//
	// https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#3232-vulnerabilities-property---cve
	CVE string `json:"cve"`

	// The MITRE standard Common Weakness Enumeration (CWE) for the weakness associated.
	//
	// https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#3233-vulnerabilities-property---cwe
	CWE CWEInfo `json:"cwe"`

	// List of IDs represents a list of unique labels or tracking IDs for the vulnerability (if such information exists).
	//
	// https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#3236-vulnerabilities-property---ids
	IDs []TrackingID `json:"ids"`

	// Provide details on the status of the referenced product related to the vulnerability.
	//
	// https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#3239-vulnerabilities-property---product-status
	ProductStatus map[string][]string `json:"product_status"`

	// Provide details of threats associated with a vulnerability.
	//
	// https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#32314-vulnerabilities-property---threats
	Threats []ThreatData `json:"threats"`

	// Vulnerability references holds a list of references associated with this vulnerability item.
	//
	// https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#32310-vulnerabilities-property---references
	References []Reference `json:"references"`

	ReleaseDate time.Time `json:"release_date"`

	// Holds a list of score objects for the current vulnerability.
	//
	// https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#32313-vulnerabilities-property---scores
	Scores []Score `json:"scores"`
}

// The MITRE standard Common Weakness Enumeration (CWE) for the weakness associated.
//
// https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#3233-vulnerabilities-property---cwe
type CWEInfo struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type Score struct {
	Products []string      `json:"products"`
	CVSSV3   *CVSSV3Schema `json:"cvss_v3,omitempty"`
	CVSSV2   *CVSSV2Schema `json:"cvss_v2,omitempty"`
}

type CVSSV3Schema struct {
	Version                       string  `json:"version"`
	VectorString                  string  `json:"vectorString"`
	BaseScore                     float64 `json:"baseScore"`
	BaseSeverity                  string  `json:"baseSeverity"`
	AttackVector                  string  `json:"attackVector,omitempty"`
	AttackComplexity              string  `json:"attackComplexity,omitempty"`
	PrivilegesRequired            string  `json:"privilegesRequired,omitempty"`
	UserInteraction               string  `json:"userInteraction,omitempty"`
	Scope                         string  `json:"scope,omitempty"`
	ConfidentialityImpact         string  `json:"confidentialityImpact,omitempty"`
	IntegrityImpact               string  `json:"integrityImpact,omitempty"`
	AvailabilityImpact            string  `json:"availabilityImpact,omitempty"`
	ExploitCodeMaturity           string  `json:"exploitCodeMaturity,omitempty"`
	RemediationLevel              string  `json:"remediationLevel,omitempty"`
	ReportConfidence              string  `json:"reportConfidence,omitempty"`
	TemporalScore                 float64 `json:"temporalScore,omitempty"`
	TemporalSeverity              string  `json:"temporalSeverity,omitempty"`
	ConfidentialityRequirement    string  `json:"confidentialityRequirement,omitempty"`
	IntegrityRequirement          string  `json:"integrityRequirement,omitempty"`
	AvailabilityRequirement       string  `json:"availabilityRequirement,omitempty"`
	ModifiedAttackVector          string  `json:"modifiedAttackVector,omitempty"`
	ModifiedAttackComplexity      string  `json:"modifiedAttackComplexity,omitempty"`
	ModifiedPrivilegesRequired    string  `json:"modifiedPrivilegesRequired,omitempty"`
	ModifiedUserInteraction       string  `json:"modifiedUserInteraction,omitempty"`
	ModifiedScope                 string  `json:"modifiedScope,omitempty"`
	ModifiedConfidentialityImpact string  `json:"modifiedConfidentialityImpact,omitempty"`
	ModifiedIntegrityImpact       string  `json:"modifiedIntegrityImpact,omitempty"`
	ModifiedAvailabilityImpact    string  `json:"modifiedAvailabilityImpact,omitempty"`
	EnvironmentalScore            float64 `json:"environmentalScore,omitempty"`
	EnvironmentalSeverity         string  `json:"environmentalSeverity,omitempty"`
}

type CVSSV2Schema struct {
	Version                    string  `json:"version"`
	VectorString               string  `json:"vectorString"`
	BaseScore                  float64 `json:"baseScore"`
	BaseSeverity               string  `json:"baseSeverity"`
	AccessVector               string  `json:"accessVector,omitempty"`
	AccessComplexity           string  `json:"accessComplexity,omitempty"`
	Authentication             string  `json:"authentication,omitempty"`
	ConfidentialityImpact      string  `json:"confidentialityImpact,omitempty"`
	IntegrityImpact            string  `json:"integrityImpact,omitempty"`
	AvailabilityImpact         string  `json:"availabilityImpact,omitempty"`
	Exploitability             string  `json:"exploitability,omitempty"`
	RemediationLevel           string  `json:"remediationLevel,omitempty"`
	ReportConfidence           string  `json:"reportConfidence,omitempty"`
	TemporalScore              float64 `json:"temporalScore,omitempty"`
	CollateralDamagePotential  string  `json:"collateralDamagePotential,omitempty"`
	TargetDistribution         string  `json:"targetDistribution,omitempty"`
	ConfidentialityRequirement string  `json:"confidentialityRequirement,omitempty"`
	IntegrityRequirement       string  `json:"integrityRequirement,omitempty"`
	AvailabilityRequirement    string  `json:"availabilityRequirement,omitempty"`
	EnvironmentalScore         float64 `json:"environmentalScore,omitempty"`
}

// Every ID item with the two mandatory properties System Name (system_name) and Text (text) contains a single unique label or tracking ID for the vulnerability.
//
// https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#3236-vulnerabilities-property---ids
type TrackingID struct {
	SystemName string `json:"system_name"`
	Text       string `json:"text"`
}

// ThreatData contains information about a threat to a product.
//
// https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#32314-vulnerabilities-property---threats
type ThreatData struct {
	Category   string   `json:"category"`
	Details    string   `json:"details"`
	ProductIDs []string `json:"product_ids"`
}

// ProductBranch is a recursive struct that contains information about a product and
// its nested products.
//
// https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#3221-product-tree-property---branches
type ProductBranch struct {
	Category string          `json:"category"`
	Name     string          `json:"name"`
	Branches []ProductBranch `json:"branches"`
	Product  Product         `json:"product,omitempty"`
}

// Product contains information used to identify a product.
//
// https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#3124-branches-type---product
type Product struct {
	Name                 string            `json:"name"`
	ID                   string            `json:"product_id"`
	IdentificationHelper map[string]string `json:"product_identification_helper"`
}

// Open reads and parses a given file path and returns a CSAF document
// or an error if the file could not be opened or parsed.
func Open(path string) (*CSAF, error) {
	fh, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("csaf: failed to open document: %w", err)
	}
	defer fh.Close()

	csafDoc := &CSAF{}
	err = json.NewDecoder(fh).Decode(csafDoc)
	if err != nil {
		return nil, fmt.Errorf("csaf: failed to decode document: %w", err)
	}

	return csafDoc, nil
}

// FirstProductName returns the first product name in the product tree
// or an empty string if no product name is found.
func (csafDoc *CSAF) FirstProductName() string {
	return csafDoc.ProductTree.FindFirstProduct()
}

// FindFirstProduct recursively searches for the first product identifier in the tree
// and returns it or an empty string if no product identifier is found.
func (branch *ProductBranch) FindFirstProduct() string {
	if branch.Product.ID != "" {
		return branch.Product.ID
	}

	// No nested branches
	if branch.Branches == nil {
		return ""
	}

	// Recursively search for the first product	identifier
	for _, b := range branch.Branches {
		if p := b.FindFirstProduct(); p != "" {
			return p
		}
	}

	return ""
}

// FindFirstProductName recursively searches for the first product name in the tree
// and returns it or an empty string if no product name is found.
func (branch *ProductBranch) FindFirstProductName() string {
	if branch.Product.Name != "" {
		return branch.Product.Name
	}

	// No nested branches
	if branch.Branches == nil {
		return ""
	}

	// Recursively search for the first product	identifier
	for _, b := range branch.Branches {
		if p := b.FindFirstProductName(); p != "" {
			return p
		}
	}

	return ""
}

// FindProductIdentifier recursively searches for the first product identifier in the tree
func (branch *ProductBranch) FindProductIdentifier(helperType, helperValue string) *Product {
	if len(branch.Product.IdentificationHelper) != 0 {
		for k := range branch.Product.IdentificationHelper {
			if k != helperType {
				continue
			}
			if branch.Product.IdentificationHelper[k] == helperValue {
				return &branch.Product
			}
		}
	}

	// No nested branches
	if branch.Branches == nil {
		return nil
	}

	// Recursively search for the first identifier
	for _, b := range branch.Branches {
		if p := b.FindProductIdentifier(helperType, helperValue); p != nil {
			return p
		}
	}

	return nil
}
