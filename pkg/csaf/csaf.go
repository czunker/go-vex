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

	// Provide details of remediations associated with a Vulnerability
	//
	// https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#32312-vulnerabilities-property---remediations
	Remediations []RemediationData `json:"remediations"`

	// Machine readable flags for products related to vulnerability
	//
	// https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#3235-vulnerabilities-property---flags
	Flags []Flag `json:"flags"`

	// Vulnerability references holds a list of references associated with this vulnerability item.
	//
	// https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#32310-vulnerabilities-property---references
	References []Reference `json:"references"`

	ReleaseDate time.Time `json:"release_date"`
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

// RemediationData contains information about how to remediate a vulnerability for a set of products.
//
// https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#32312-vulnerabilities-property---remediations
type RemediationData struct {
	Category     string      `json:"category"`
	Date         time.Time   `json:"date"`
	Details      string      `json:"details"`
	Entitlements []string    `json:"entitlements"`
	GroupIDs     []string    `json:"group_ids"`
	ProductIDs   []string    `json:"product_ids"`
	Restart      RestartData `json:"restart_required"`
}

// Remediation instructions for restart of affected software.
//
// https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#323127-vulnerabilities-property---remediations---restart-required
type RestartData struct {
	Category string `json:"category"`
	Details  string `json:"details"`
}

// Machine readable flags for products related to the Vulnerability
//
// https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#3235-vulnerabilities-property---flags
type Flag struct {
	Label      string    `json:"label"`
	Date       time.Time `json:"date"`
	GroupIDs   []string  `json:"group_ids"`
	ProductIDs []string  `json:"product_ids"`
}

// ProductBranch is a recursive struct that contains information about a product and
// its nested products.
//
// https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#3221-product-tree-property---branches
type ProductBranch struct {
	Category      string          `json:"category"`
	Name          string          `json:"name"`
	Branches      []ProductBranch `json:"branches"`
	Product       Product         `json:"product,omitempty"`
	Relationships []Relationship  `json:"relationships"`
}

// Relationship establishes a link between two existing full_product_name_t elements, allowing
// the document producer to define a combination of two products that form a new full_product_name entry.
//
// https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#3224-product-tree-property---relationships
type Relationship struct {
	Category            string  `json:"category"`
	FullProductName     Product `json:"full_product_name"`
	ProductRef          string  `json:"product_reference"`
	RelatesToProductRef string  `json:"relates_to_product_reference"`
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

type ProductList []Product

// Add adds a prodocut to the product list if its not there, matching id and
// software identifiers.
func (pl *ProductList) Add(p Product) {
	if p.ID == "" && len(p.IdentificationHelper) == 0 {
		return
	}
	helpers := map[string]struct{}{}

	for _, ih := range p.IdentificationHelper {
		helpers[ih] = struct{}{}
	}
	for _, tp := range *pl {
		if tp.ID == p.ID {
			return
		}
		for _, idhelper := range tp.IdentificationHelper {
			if _, ok := helpers[idhelper]; ok {
				return
			}
		}
	}
	*pl = append(ProductList{p}, *pl...)
}

// ListProducts returns a flat list of all products in the branch
func (branch *ProductBranch) ListProducts() ProductList {
	list := ProductList{}
	list.Add(branch.Product)
	for _, b := range branch.Branches {
		for _, p := range b.ListProducts() {
			list.Add(p)
		}
	}
	return list
}

func (csafDoc *CSAF) ListProducts() ProductList {
	prods := ProductList{}
	for _, b := range csafDoc.ProductTree.Branches {
		brachProds := b.ListProducts()
		for _, sp := range brachProds {
			prods.Add(sp)
		}
	}
	return prods
}
