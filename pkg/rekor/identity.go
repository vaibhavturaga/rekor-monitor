// Copyright 2022 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package rekor

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/go-openapi/runtime"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/pki"
	"github.com/sigstore/rekor/pkg/types"
	"github.com/sigstore/sigstore/pkg/cryptoutils"

	// required imports to call init methods
	_ "github.com/sigstore/rekor/pkg/types/alpine/v0.0.1"
	_ "github.com/sigstore/rekor/pkg/types/cose/v0.0.1"
	_ "github.com/sigstore/rekor/pkg/types/dsse/v0.0.1"
	_ "github.com/sigstore/rekor/pkg/types/hashedrekord/v0.0.1"
	_ "github.com/sigstore/rekor/pkg/types/helm/v0.0.1"
	_ "github.com/sigstore/rekor/pkg/types/intoto/v0.0.1"
	_ "github.com/sigstore/rekor/pkg/types/intoto/v0.0.2"
	_ "github.com/sigstore/rekor/pkg/types/jar/v0.0.1"
	_ "github.com/sigstore/rekor/pkg/types/rekord/v0.0.1"
	_ "github.com/sigstore/rekor/pkg/types/rfc3161/v0.0.1"
	_ "github.com/sigstore/rekor/pkg/types/rpm/v0.0.1"
	_ "github.com/sigstore/rekor/pkg/types/tuf/v0.0.1"
)

var (
	CertExtensionOIDCIssuerV2 = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 8}
)

// CertificateIdentity holds a certificate subject and an optional list of identity issuers
type CertificateIdentity struct {
	CertSubject string   `yaml:"certSubject"`
	Issuers     []string `yaml:"issuers"`
}

type OIDconstraint struct {
	OID        []int  `yaml:"oid"`
	Constraint []byte `yaml:"constraint"`
}

// MonitoredValues holds a set of values to compare against a given entry
type MonitoredValues struct {
	// CertificateIdentities contains a list of subjects and issuers
	CertificateIdentities []CertificateIdentity `yaml:"certIdentities"`
	// Fingerprints contains a list of key fingerprints. Values are as follows:
	// For keys, certificates, and minisign, hex-encoded SHA-256 digest
	// of the DER-encoded PKIX public key or certificate
	// For SSH and PGP, the standard for each ecosystem:
	// For SSH, unpadded base-64 encoded SHA-256 digest of the key
	// For PGP, hex-encoded SHA-1 digest of a key, which can be either
	// a primary key or subkey
	Fingerprints []string `yaml:"fingerprints"`
	// Subjects contains a list of subjects that are not specified in a
	// certificate, such as a SSH key or PGP key email address
	Subjects []string `yaml:"subjects"`
	// OIDConstraints contains a list of OIDs and constraints to be checked
	OIDConstraints []OIDconstraint `yaml:"oidConstraints"`
}

// IdentityEntry holds a certificate subject, issuer, and log entry metadata
type IdentityEntry struct {
	CertSubject string
	Issuer      string
	Fingerprint string
	Subject     string
	Index       int64
	UUID        string
}

func (e *IdentityEntry) String() string {
	var parts []string
	for _, s := range []string{e.CertSubject, e.Issuer, e.Fingerprint, e.Subject, strconv.Itoa(int(e.Index)), e.UUID} {
		if strings.TrimSpace(s) != "" {
			parts = append(parts, s)
		}
	}
	return strings.Join(parts, " ")
}

// MatchedIndices returns a list of log indices that contain the requested identities.
func MatchedIndices(logEntries []models.LogEntry, mvs MonitoredValues) ([]IdentityEntry, error) {
	if err := verifyMonitoredValues(mvs); err != nil {
		return nil, err
	}

	var matchedEntries []IdentityEntry

	for _, entries := range logEntries {
		for uuid, entry := range entries {
			entry := entry

			verifiers, err := extractVerifiers(&entry)
			if err != nil {
				return nil, fmt.Errorf("error extracting verifiers for UUID %s at index %d: %w", uuid, *entry.LogIndex, err)
			}
			subjects, certs, fps, err := extractAllIdentities(verifiers)
			if err != nil {
				return nil, fmt.Errorf("error extracting identities for UUID %s at index %d: %w", uuid, *entry.LogIndex, err)
			}

			monitoredFpSet := make(map[IdentityEntry]struct{})
			for _, monitoredFp := range mvs.Fingerprints {
				for _, fp := range fps {
					if fp == monitoredFp {
						monitoredFpSet[IdentityEntry{
							Fingerprint: fp,
							Index:       *entry.LogIndex,
							UUID:        uuid,
						}] = struct{}{}
					}
				}
			}

			monitoredSubSet := make(map[IdentityEntry]struct{})
			for _, monitoredSub := range mvs.Subjects {
				regex, err := regexp.Compile(monitoredSub)
				if err != nil {
					return nil, fmt.Errorf("error compiling regex for UUID %s at index %d: %w", uuid, *entry.LogIndex, err)
				}
				for _, sub := range subjects {
					if regex.MatchString(sub) {
						monitoredSubSet[IdentityEntry{
							Subject: sub,
							Index:   *entry.LogIndex,
							UUID:    uuid,
						}] = struct{}{}
					}
				}
			}

			monitoredCertIDSet := make(map[IdentityEntry]struct{})
			oidConstraintSet := make(map[IdentityEntry]struct{})
			for _, cert := range certs {
				for _, monitoredCertID := range mvs.CertificateIdentities {
					certIDMatch, certIDSub, certIDIss, certIDErr := certMatchesPolicy(cert, monitoredCertID.CertSubject, monitoredCertID.Issuers)
					if certIDErr != nil {
						return nil, fmt.Errorf("error with policy matching for UUID %s at index %d: %w", uuid, *entry.LogIndex, certIDErr)
					} else if certIDMatch {
						monitoredCertIDSet[IdentityEntry{
							CertSubject: certIDSub,
							Issuer:      certIDIss,
							Index:       *entry.LogIndex,
							UUID:        uuid,
						}] = struct{}{}
					}
				}

				for _, OIDConstraint := range mvs.OIDConstraints {
					oidMatch, oidErr := oidMatchesPolicy(cert, asn1.ObjectIdentifier(OIDConstraint.OID), OIDConstraint.Constraint)
					if oidErr != nil {
						return nil, fmt.Errorf("error with policy matching for UUID %s at index %d: %w", uuid, *entry.LogIndex, oidErr)
					} else if oidMatch {
						oidConstraintSet[IdentityEntry{
							// TODO: What else should I put here...
							Index: *entry.LogIndex,
							UUID:  uuid,
						}] = struct{}{}
					}
				}
			}

			// Find intersection of all sets and add to array
			intersect := intersection(monitoredFpSet, intersection(monitoredSubSet, intersection(monitoredCertIDSet, oidConstraintSet)))
			for key := range intersect {
				matchedEntries = append(matchedEntries, key)
			}
		}
	}

	return matchedEntries, nil
}

// verifyMonitoredValues checks that monitored values are valid
func verifyMonitoredValues(mvs MonitoredValues) error {
	if len(mvs.CertificateIdentities) == 0 && len(mvs.Fingerprints) == 0 && len(mvs.Subjects) == 0 {
		return errors.New("no identities provided to monitor")
	}
	for _, certID := range mvs.CertificateIdentities {
		if len(certID.CertSubject) == 0 {
			return errors.New("certificate subject empty")
		}
		// issuers can be empty
		for _, iss := range certID.Issuers {
			if len(iss) == 0 {
				return errors.New("issuer empty")
			}
		}
	}
	for _, oids := range mvs.OIDConstraints {
		if len(oids.OID) == 0 {
			return errors.New("oid empty")
		}
		// constraint must be set
		for _, constraint := range oids.Constraint {
			if constraint == 0 {
				return errors.New("oid constraint not set")
			}
		}
	}
	for _, fp := range mvs.Fingerprints {
		if len(fp) == 0 {
			return errors.New("fingerprint empty")
		}
	}
	for _, sub := range mvs.Subjects {
		if len(sub) == 0 {
			return errors.New("subject empty")
		}
	}
	return nil
}

// extractVerifiers extracts a set of keys or certificates that can verify an
// artifact signature from a Rekor entry
func extractVerifiers(e *models.LogEntryAnon) ([]pki.PublicKey, error) {
	b, err := base64.StdEncoding.DecodeString(e.Body.(string))
	if err != nil {
		return nil, err
	}

	pe, err := models.UnmarshalProposedEntry(bytes.NewReader(b), runtime.JSONConsumer())
	if err != nil {
		return nil, err
	}

	eimpl, err := types.UnmarshalEntry(pe)
	if err != nil {
		return nil, err
	}

	return eimpl.Verifiers()
}

// extractAllIdentities gets all certificates, email addresses, and key fingerprints
// from a list of verifiers
func extractAllIdentities(verifiers []pki.PublicKey) ([]string, []*x509.Certificate, []string, error) {
	var subjects []string
	var certificates []*x509.Certificate
	var fps []string

	for _, v := range verifiers {
		// append all verifier subjects (email or SAN)
		subjects = append(subjects, v.Subjects()...)
		ids, err := v.Identities()
		if err != nil {
			return nil, nil, nil, err
		}
		// append all certificate and key fingerprints
		for _, i := range ids {
			fps = append(fps, i.Fingerprint)
			if cert, ok := i.Crypto.(*x509.Certificate); ok {
				certificates = append(certificates, cert)
			}
		}
	}
	return subjects, certificates, fps, nil
}

// getExtension gets a certificate extension by OID
func getExtension(cert *x509.Certificate, oid asn1.ObjectIdentifier) (string, error) {
	for _, ext := range cert.Extensions {
		if !ext.Id.Equal(oid) {
			continue
		}
		var extValue string
		rest, err := asn1.Unmarshal(ext.Value, &extValue)
		if err != nil {
			return "", fmt.Errorf("%w", err)
		}
		if len(rest) != 0 {
			return "", fmt.Errorf("unmarshalling extension had rest for oid %v", oid)
		}
		return extValue, nil
	}
	return "", nil
}

// certMatchesPolicy returns true if a certificate contains a given subject and optionally a given issuer
// expectedSub and expectedIssuers can be regular expressions
// certMatchesPolicy also returns the matched subject and issuer on success
func certMatchesPolicy(cert *x509.Certificate, expectedSub string, expectedIssuers []string) (bool, string, string, error) {
	sans := cryptoutils.GetSubjectAlternateNames(cert)
	issuer, err := getExtension(cert, CertExtensionOIDCIssuerV2)
	if err != nil {
		return false, "", "", err
	}
	subjectMatches := false
	regex, err := regexp.Compile(expectedSub)
	if err != nil {
		return false, "", "", fmt.Errorf("malformed subject regex: %w", err)
	}
	matchedSub := ""
	for _, sub := range sans {
		if regex.MatchString(sub) {
			subjectMatches = true
			matchedSub = sub
		}
	}
	// allow any issuer
	if len(expectedIssuers) == 0 {
		return subjectMatches, matchedSub, issuer, nil
	}

	issuerMatches := false
	for _, expectedIss := range expectedIssuers {
		regex, err := regexp.Compile(expectedIss)
		if err != nil {
			return false, "", "", fmt.Errorf("malformed issuer regex: %w", err)
		}
		if regex.MatchString(issuer) {
			issuerMatches = true
		}
	}
	return subjectMatches && issuerMatches, matchedSub, issuer, nil
}

// oidMatchesPolicy returns true if the OID value matches one of the provided constraints
func oidMatchesPolicy(cert *x509.Certificate, oid asn1.ObjectIdentifier, oidConstraint []byte) (bool, error) {
	value, err := getExtension(cert, oid)
	if err != nil {
		return false, fmt.Errorf("error getting extension value: %w", err)
	}
	if value == "" {
		return false, fmt.Errorf("OID %s not present in the certificate", oid)
	}

	var extValue []byte
	rest, err := asn1.Unmarshal([]byte(value), &extValue)
	if err != nil {
		return false, fmt.Errorf("error unmarshalling extension value: %w", err)
	}
	if len(rest) > 0 {
		return false, fmt.Errorf("unmarshalling extension had rest for oid %v", oid)
	}
	//compare the value with the constraint
	if !compareValue(extValue, oidConstraint) {
		return false, fmt.Errorf("OID %s exists but does not match the expected value", oid)
	}

	return true, nil
}

// Helper functions

// compareValue compares two byte arrays for equality
func compareValue(value []byte, target []byte) bool {
	if len(value) != len(target) {
		return false
	}
	for i := range value {
		if value[i] != target[i] {
			return false
		}
	}
	return true
}

// takes in two sets and finds the intserction
func intersection(set1, set2 map[IdentityEntry]struct{}) map[IdentityEntry]struct{} {
	result := make(map[IdentityEntry]struct{})

	for key := range set1 {
		if _, ok := set2[key]; ok {
			result[key] = struct{}{}
		}
	}

	return result
}
