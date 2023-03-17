/*
Copyright 2023 The OpenVEX Authors
SPDX-License-Identifier: Apache-2.0
*/

package csaf

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestOpen(t *testing.T) {
	doc, err := Open("testdata/csaf.json")
	require.NoError(t, err)
	require.NotNil(t, doc)
	require.Equal(t, "Example VEX Document", doc.Document.Title)
	require.Equal(t, "CSAFPID-0001", doc.FirstProductName())

	// Vulnerabilities
	require.Len(t, doc.Vulnerabilities, 1)
	require.Equal(t, doc.Vulnerabilities[0].CVE, "CVE-2009-4487")
	require.Len(t, doc.Vulnerabilities[0].ProductStatus, 1)
	require.Len(t, doc.Vulnerabilities[0].ProductStatus["known_not_affected"], 1)
	require.Equal(t, doc.Vulnerabilities[0].ProductStatus["known_not_affected"][0], "CSAFPID-0001")
}

func TestOpenRHAdvisory(t *testing.T) {
	doc, err := Open("testdata/rhsa-2020_1358.json")
	require.NoError(t, err)
	require.NotNil(t, doc)
	require.Equal(t, "Red Hat Security Advisory: virt:rhel security and bug fix update", doc.Document.Title)
	require.Equal(t, "AppStream-8.1.0.Z.MAIN.EUS", doc.FirstProductName())

	require.Equal(t, "Important", doc.Document.AggregateSeverity.Text)
	require.Equal(t, "CWE-122", doc.Vulnerabilities[0].CWE.ID)
	require.Equal(t, "https://bugzilla.redhat.com/show_bug.cgi?id=1794290", doc.Vulnerabilities[0].IDs[0].Text)
	require.Equal(t, "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:L/I:L/A:L", doc.Vulnerabilities[0].Scores[0].CVSSV3.VectorString)
}

func TestFindFirstProduct(t *testing.T) {
	doc, err := Open("testdata/csaf.json")
	require.NoError(t, err)
	require.NotNil(t, doc)

	prod := doc.ProductTree.FindFirstProduct()
	require.Equal(t, prod, "CSAFPID-0001")
}

func TestFindByHelper(t *testing.T) {
	doc, err := Open("testdata/csaf.json")
	require.NoError(t, err)
	require.NotNil(t, doc)

	prod := doc.ProductTree.FindProductIdentifier("purl", "pkg:maven/@1.3.4")
	require.NotNil(t, prod)
	require.Equal(t, prod.ID, "CSAFPID-0001")
}
