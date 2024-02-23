//
// Copyright 2021 The Sigstore Authors.
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

package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/sigstore/rekor-monitor/pkg/rekor"
	file "github.com/sigstore/rekor-monitor/pkg/util"
	"github.com/sigstore/rekor/pkg/client"
	gclient "github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/client/entries"
	"github.com/sigstore/rekor/pkg/util"
	"github.com/sigstore/rekor/pkg/verify"
	"github.com/sigstore/sigstore/pkg/signature"
	"gopkg.in/yaml.v3"
)

// Default values for monitoring job parameters
const (
	publicRekorServerURL     = "https://rekor.sigstore.dev"
	logInfoFileName          = "logInfo.txt"
	outputIdentitiesFileName = "identities.txt"
)

func getEntryByIndex(index uint64, rekorClient *gclient.Rekor) (entries.GetLogEntryByIndexOK, error) {
	// Create the params object
	params := entries.NewGetLogEntryByIndexParams()
	params.LogIndex = int64(index) // Convert uint64 to int64 as LogIndex expects int64

	// Fetch the entry using its index
	entry, err := rekorClient.Entries.GetLogEntryByIndex(params)
	if err != nil {
		return *entry, fmt.Errorf("error getting entry by index: %v", err) // TODO: I assume *entry isn't valid here
	}
	return *entry, nil
}

func checkEntries(height uint64, rekorClient *gclient.Rekor, logInfoFile *string) error {
	// Check if the logInfoFile exists and has data
	fi, err := os.Stat(*logInfoFile)
	if fi.Size() == 0 {
		return fmt.Errorf("log info file is empty")
	}
	if err != nil {
		return fmt.Errorf("error checking file: %v", err)
	}

	// Read the latest checkpoint from the file
	prevCheckpoint, err := file.ReadLatestCheckpoint(*logInfoFile)
	if err != nil {
		return fmt.Errorf("reading checkpoint log: %v", err)
	}

	// Calculate the base checkpoint size to iterate over
	var baseCheckpointSize uint64
	if prevCheckpoint.Size > height {
		baseCheckpointSize = prevCheckpoint.Size - height
	}

	// Iterate over the entries starting from baseCheckpointSize
	for i := baseCheckpointSize; i < prevCheckpoint.Size; i++ {
		// Attempt to get the entry
		entry, err := getEntryByIndex(i, rekorClient)
		if err != nil {
			return err
		}

		// Print information from the entry
		fmt.Printf("Entry %d: %s\n", i, entry.String())
	}
	// Print whole previous checkpoint
	fmt.Println(prevCheckpoint)

	return nil
}

// runConsistencyCheck periodically verifies the root hash consistency of a Rekor log.
func runConsistencyCheck(interval *time.Duration, rekorClient *gclient.Rekor, verifier signature.Verifier, logInfoFile *string, mvs rekor.MonitoredValues, outputIdentitiesFile *string, once *bool) (error, uint64) {
	ticker := time.NewTicker(*interval)
	height := uint64(0)
	defer ticker.Stop()

	// Loop will:
	// 1. Fetch latest checkpoint and verify
	// 2. If old checkpoint is present, verify consistency proof
	// 3. Write latest checkpoint to file

	// To get an immediate first tick
	for ; ; <-ticker.C {
		logInfo, err := rekor.GetLogInfo(context.Background(), rekorClient)
		if err != nil {
			return fmt.Errorf("getting log info: %v", err), 0
		}
		checkpoint := &util.SignedCheckpoint{}
		if err := checkpoint.UnmarshalText([]byte(*logInfo.SignedTreeHead)); err != nil {
			return fmt.Errorf("unmarshalling logInfo.SignedTreeHead to Checkpoint: %v", err), 0
		}
		if !checkpoint.Verify(verifier) {
			return fmt.Errorf("verifying checkpoint (size %d, hash %s) failed", checkpoint.Size, hex.EncodeToString(checkpoint.Hash)), 75
		}

		fi, err := os.Stat(*logInfoFile)
		var prevCheckpoint *util.SignedCheckpoint
		if err == nil && fi.Size() != 0 {
			// File containing previous checkpoints exists
			prevCheckpoint, err = file.ReadLatestCheckpoint(*logInfoFile)
			if err != nil {
				return fmt.Errorf("reading checkpoint log: %v", err), 0
			}
			if !prevCheckpoint.Verify(verifier) {
				return fmt.Errorf("verifying checkpoint (size %d, hash %s) failed", checkpoint.Size, hex.EncodeToString(checkpoint.Hash)), 0
			}
		}
		if prevCheckpoint != nil {
			if err := verify.ProveConsistency(context.Background(), rekorClient, prevCheckpoint, checkpoint, *logInfo.TreeID); err != nil {
				return fmt.Errorf("failed to verify log consistency: %v", err), 0
			}
			fmt.Fprintf(os.Stderr, "Root hash consistency verified - Current Size: %d Root Hash: %s - Previous Size: %d Root Hash %s\n",
				checkpoint.Size, hex.EncodeToString(checkpoint.Hash), prevCheckpoint.Size, hex.EncodeToString(prevCheckpoint.Hash))
			fmt.Fprintf(os.Stderr, "Change in size: %d\n", checkpoint.Size-prevCheckpoint.Size)
			height = checkpoint.Size - prevCheckpoint.Size
		}

		// Write if there was no stored checkpoint or the sizes differ
		if prevCheckpoint == nil || prevCheckpoint.Size != checkpoint.Size {
			if err := file.WriteCheckpoint(checkpoint, *logInfoFile); err != nil {
				return fmt.Errorf("failed to write checkpoint: %v", err), 0
			}
		}

		// TODO: Switch to writing checkpoints to GitHub so that the history is preserved. Then we only need
		// to persist the last checkpoint.
		// Delete old checkpoints to avoid the log growing indefinitely
		if err := file.DeleteOldCheckpoints(*logInfoFile); err != nil {
			return fmt.Errorf("failed to delete old checkpoints: %v", err), 0
		}

		// Look for identities if there was a previous, different checkpoint
		if prevCheckpoint != nil && prevCheckpoint.Size != checkpoint.Size {
			// Get log size of inactive shards
			totalSize := 0
			for _, s := range logInfo.InactiveShards {
				totalSize += int(*s.TreeSize)
			}
			startIndex := int(prevCheckpoint.Size) + totalSize - 1
			endIndex := int(checkpoint.Size) + totalSize - 1

			// Search for identities in the log range
			if len(mvs.CertificateIdentities) > 0 || len(mvs.Fingerprints) > 0 || len(mvs.Subjects) > 0 {
				entries, err := rekor.GetEntriesByIndexRange(context.Background(), rekorClient, startIndex, endIndex)
				if err != nil {
					return fmt.Errorf("error getting entries by index range: %v", err), 0
				}
				idEntries, err := rekor.MatchedIndices(entries, mvs)
				if err != nil {
					return fmt.Errorf("error finding log indices: %v", err), 0
				}

				if len(idEntries) > 0 {
					for _, idEntry := range idEntries {
						fmt.Fprintf(os.Stderr, "Found %s\n", idEntry.String())

						if err := file.WriteIdentity(*outputIdentitiesFile, idEntry); err != nil {
							return fmt.Errorf("failed to write entry: %v", err), 0
						}
					}
				}
			}
		}

		if *once {
			return nil, height
		}
	}
}

// This main function performs a periodic root hash consistency check.
// Upon starting, any existing latest snapshot data is loaded and the function runs
// indefinitely to perform consistency check for every time interval that was specified.
func main() {
	// Command-line flags that are parameters to the verifier job
	serverURL := flag.String("url", publicRekorServerURL, "URL to the rekor server that is to be monitored")
	interval := flag.Duration("interval", 5*time.Minute, "Length of interval between each periodical consistency check")
	logInfoFile := flag.String("file", logInfoFileName, "Name of the file containing initial merkle tree information")
	once := flag.Bool("once", false, "Perform consistency check once and exit")
	yourName := flag.String("name", "default", "Name of the user executing the program")
	monitoredValsInput := flag.String("monitored-values", "", "yaml of certificate subjects and issuers, key subjects, "+
		"and fingerprints. For certificates, if no issuers are specified, match any OIDC provider.")
	outputIdentitiesFile := flag.String("output-identities", outputIdentitiesFileName,
		"Name of the file containing indices and identities found in the log. Format is \"subject issuer index uuid\"")
	height := uint64(0)
	flag.Parse()

	if *yourName != "default" {
		flag.Set("once", "true")
	}

	var monitoredVals rekor.MonitoredValues
	if err := yaml.Unmarshal([]byte(*monitoredValsInput), &monitoredVals); err != nil {
		log.Fatalf("error parsing identities: %v", err)
	}
	for _, certID := range monitoredVals.CertificateIdentities {
		if len(certID.Issuers) == 0 {
			fmt.Printf("Monitoring certificate subject %s\n", certID.CertSubject)
		} else {
			fmt.Printf("Monitoring certificate subject %s for issuer(s) %s\n", certID.CertSubject, strings.Join(certID.Issuers, ","))
		}
	}
	for _, fp := range monitoredVals.Fingerprints {
		fmt.Printf("Monitoring fingerprint %s\n", fp)
	}
	for _, sub := range monitoredVals.Subjects {
		fmt.Printf("Monitoring subject %s\n", sub)
	}

	rekorClient, err := client.GetRekorClient(*serverURL)
	if err != nil {
		log.Fatalf("getting Rekor client: %v", err)
	}

	verifier, err := rekor.GetLogVerifier(context.Background(), rekorClient)
	if err != nil {
		log.Fatal(err)
	}

	err, height = runConsistencyCheck(interval, rekorClient, verifier, logInfoFile, monitoredVals, outputIdentitiesFile, once)
	if err != nil {
		log.Fatalf("%v", err)
	}

	checkEntries(height, rekorClient, logInfoFile)
}
