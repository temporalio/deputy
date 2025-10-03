package index

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestMakeKey(t *testing.T) {
	tests := []struct {
		name     string
		parts    []string
		expected string
	}{
		{
			name:     "empty key",
			parts:    []string{},
			expected: "",
		},
		{
			name:     "single part",
			parts:    []string{"security"},
			expected: "security\x00",
		},
		{
			name:     "two parts",
			parts:    []string{"security", "vulnerability"},
			expected: "security\x00vulnerability\x00",
		},
		{
			name:     "full artifact key components",
			parts:    []string{"security", "vulnerability", "pkg:npm/lodash@4.17.21", "2025-10-03T10:30:00.123456789Z", "CVE-2023-1234"},
			expected: "security\x00vulnerability\x00pkg:npm/lodash@4.17.21\x002025-10-03T10:30:00.123456789Z\x00CVE-2023-1234\x00",
		},
		{
			name:     "parts with special characters",
			parts:    []string{"namespace", "type", "entity:with/slashes", "2025-10-03T10:30:00Z", "id-with-dashes"},
			expected: "namespace\x00type\x00entity:with/slashes\x002025-10-03T10:30:00Z\x00id-with-dashes\x00",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := makeKey(tt.parts...)
			if string(result) != tt.expected {
				t.Errorf("makeKey(%v) = %q, expected %q", tt.parts, string(result), tt.expected)
			}
		})
	}
}

func TestMakeArtifactKey(t *testing.T) {
	tests := []struct {
		name         string
		namespace    string
		artifactType string
		entityID     string
		timestamp    string
		id           string
		expected     string
	}{
		{
			name:         "security vulnerability",
			namespace:    "security",
			artifactType: "vulnerability",
			entityID:     "pkg:npm/lodash@4.17.21",
			timestamp:    "2025-10-03T10:30:00.123456789Z",
			id:           "CVE-2023-1234",
			expected:     "security\x00vulnerability\x00pkg:npm/lodash@4.17.21\x002025-10-03T10:30:00.123456789Z\x00CVE-2023-1234\x00",
		},
		{
			name:         "sca dependency",
			namespace:    "sca",
			artifactType: "dependency",
			entityID:     "repo:github.com/org/app",
			timestamp:    "2025-10-03T15:45:30.987654321Z",
			id:           "dep-lodash-4.17.21",
			expected:     "sca\x00dependency\x00repo:github.com/org/app\x002025-10-03T15:45:30.987654321Z\x00dep-lodash-4.17.21\x00",
		},
		{
			name:         "sast finding",
			namespace:    "security",
			artifactType: "sast-finding",
			entityID:     "file:src/main.go",
			timestamp:    "2025-10-03T09:15:22.555000000Z",
			id:           "sql-injection-42",
			expected:     "security\x00sast-finding\x00file:src/main.go\x002025-10-03T09:15:22.555000000Z\x00sql-injection-42\x00",
		},
		{
			name:         "compliance status",
			namespace:    "compliance",
			artifactType: "status",
			entityID:     "repo:github.com/org/app",
			timestamp:    "2025-10-03T12:00:00.000000000Z",
			id:           "sox-compliance-check",
			expected:     "compliance\x00status\x00repo:github.com/org/app\x002025-10-03T12:00:00.000000000Z\x00sox-compliance-check\x00",
		},
		{
			name:         "container vulnerability",
			namespace:    "security",
			artifactType: "vulnerability",
			entityID:     "container:docker.io/nginx:1.21",
			timestamp:    "2025-10-03T18:22:11.444333222Z",
			id:           "CVE-2023-5678",
			expected:     "security\x00vulnerability\x00container:docker.io/nginx:1.21\x002025-10-03T18:22:11.444333222Z\x00CVE-2023-5678\x00",
		},
		{
			name:         "infrastructure misconfiguration",
			namespace:    "security",
			artifactType: "misconfiguration",
			entityID:     "infra:aws/s3/bucket-name",
			timestamp:    "2025-10-03T20:30:45.111222333Z",
			id:           "s3-public-read-acl",
			expected:     "security\x00misconfiguration\x00infra:aws/s3/bucket-name\x002025-10-03T20:30:45.111222333Z\x00s3-public-read-acl\x00",
		},
		{
			name:         "quality metric",
			namespace:    "quality",
			artifactType: "metric",
			entityID:     "file:src/utils.go",
			timestamp:    "2025-10-03T14:33:17.666777888Z",
			id:           "cyclomatic-complexity",
			expected:     "quality\x00metric\x00file:src/utils.go\x002025-10-03T14:33:17.666777888Z\x00cyclomatic-complexity\x00",
		},
		{
			name:         "provenance attestation",
			namespace:    "provenance",
			artifactType: "attestation",
			entityID:     "pkg:npm/lodash@4.17.21",
			timestamp:    "2025-10-03T11:45:55.999888777Z",
			id:           "slsa-v1-attestation",
			expected:     "provenance\x00attestation\x00pkg:npm/lodash@4.17.21\x002025-10-03T11:45:55.999888777Z\x00slsa-v1-attestation\x00",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := makeArtifactKey(tt.namespace, tt.artifactType, tt.entityID, tt.timestamp, tt.id)
			if string(result) != tt.expected {
				t.Errorf("makeArtifactKey(%q, %q, %q, %q, %q) = %q, expected %q",
					tt.namespace, tt.artifactType, tt.entityID, tt.timestamp, tt.id,
					string(result), tt.expected)
			}
		})
	}
}

func TestArtifactKeyFormat(t *testing.T) {
	// Test that artifacts produce the expected key format
	timestamp := time.Date(2025, 10, 3, 10, 30, 0, 123456789, time.UTC)

	artifact := Artifact{
		Namespace: "security",
		Type:      "vulnerability",
		ID:        "CVE-2023-1234",
		Entity: Entity{
			Type: "package",
			ID:   "pkg:npm/lodash@4.17.21",
		},
		Timestamp: timestamp,
	}

	expectedKey := "security\x00vulnerability\x00pkg:npm/lodash@4.17.21\x002025-10-03T10:30:00.123456789Z\x00CVE-2023-1234\x00"
	actualKey := makeArtifactKey(
		artifact.Namespace,
		artifact.Type,
		artifact.Entity.ID,
		artifact.Timestamp.Format(timeEncoding),
		artifact.ID,
	)

	if string(actualKey) != expectedKey {
		t.Errorf("Artifact key format mismatch:\nExpected: %q\nActual:   %q", expectedKey, string(actualKey))
	}
}

func TestKeyOrdering(t *testing.T) {
	// Test that keys are lexicographically ordered as expected
	keys := [][]byte{
		makeKey("compliance", "status"),
		makeKey("quality", "metric"),
		makeKey("sca", "dependency"),
		makeKey("security", "finding"),
		makeKey("security", "vulnerability"),
	}

	// Check ordering
	for i := 1; i < len(keys); i++ {
		if string(keys[i-1]) >= string(keys[i]) {
			t.Errorf("Keys not in lexicographic order: %q >= %q", string(keys[i-1]), string(keys[i]))
		}
	}
}

func TestKeyPrefixMatching(t *testing.T) {
	// Test that namespace prefixes work correctly
	securityPrefix := makeKey("security")
	securityVulnKey := makeKey("security", "vulnerability", "pkg:npm/lodash@4.17.21")

	// Security vulnerability key should start with security prefix
	if !startsWith(securityVulnKey, securityPrefix) {
		t.Errorf("Security vulnerability key %q should start with security prefix %q",
			string(securityVulnKey), string(securityPrefix))
	}

	// Different namespace should not match
	complianceKey := makeKey("compliance", "status", "repo:github.com/org/app")
	if startsWith(complianceKey, securityPrefix) {
		t.Errorf("Compliance key %q should not start with security prefix %q",
			string(complianceKey), string(securityPrefix))
	}
}

// Helper function to check if key starts with prefix
func startsWith(key, prefix []byte) bool {
	if len(prefix) > len(key) {
		return false
	}
	for i := range prefix {
		if key[i] != prefix[i] {
			return false
		}
	}
	return true
}

func TestEntityPatterns(t *testing.T) {
	// Test various entity ID patterns used in documentation
	patterns := []struct {
		entityType string
		pattern    string
		example    string
	}{
		{"Repository", "repo:<host>/<org>/<name>", "repo:github.com/org/myapp"},
		{"Package", "pkg:<ecosystem>/<name>@<version>", "pkg:npm/lodash@4.17.21"},
		{"File", "file:<path>", "file:src/main.go"},
		{"Function", "func:<file>#<name>", "func:file:src/main.go#handleRequest"},
		{"Container", "container:<registry>/<image>:<tag>", "container:docker.io/nginx:1.21"},
		{"Infrastructure", "infra:<provider>/<type>/<id>", "infra:aws/ec2/i-1234567890abcdef0"},
	}

	for _, pattern := range patterns {
		t.Run(pattern.entityType, func(t *testing.T) {
			// Test that the example entity ID can be used in a key
			key := makeArtifactKey("test", "artifact", pattern.example, "2025-10-03T10:30:00.123456789Z", "test-id")
			expectedKey := "test\x00artifact\x00" + pattern.example + "\x002025-10-03T10:30:00.123456789Z\x00test-id\x00"

			if string(key) != expectedKey {
				t.Errorf("Entity pattern %s failed:\nExpected: %q\nActual:   %q",
					pattern.entityType, expectedKey, string(key))
			}
		})
	}
}

func TestTimestampBasedAnalysis(t *testing.T) {
	// Test comprehensive timestamp-based analysis scenarios for large-scale data
	baseTime := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)

	t.Run("DependencyEvolutionOverTime", func(t *testing.T) {
		// Simulate tracking dependency changes over time
		repoEntity := "repo:github.com/org/critical-app"

		// Generate dependency events over time with distinct timestamps
		events := []struct {
			offsetHours int
			action      string
			dep         string
			version     string
		}{
			// Spread events across different hours to ensure chronological ordering
			{0, "added", "lodash", "4.17.20"},                   // Day 1
			{1, "added", "express", "4.18.0"},                   // Day 1
			{2, "added", "react", "18.2.0"},                     // Day 1
			{24, "vulnerability-detected", "lodash", "4.17.20"}, // Day 2
			{25, "updated", "lodash", "4.17.21"},                // Day 2
			{72, "added", "axios", "1.4.0"},                     // Day 4
			{96, "added", "moment", "2.29.4"},                   // Day 5
			{720, "removed", "moment", "2.29.4"},                // Day 31
			{721, "added", "date-fns", "2.30.0"},                // Day 31
			{1440, "updated", "react", "19.0.0"},                // Day 61
		}

		// Generate keys for each event
		keys := make([]string, len(events))
		for i, event := range events {
			eventTime := baseTime.Add(time.Duration(event.offsetHours) * time.Hour)

			artifactID := fmt.Sprintf("%s-%s-%s", event.action, event.dep, event.version)
			key := makeArtifactKey(
				"sca",
				"dependency-change",
				repoEntity,
				eventTime.Format(timeEncoding),
				artifactID,
			)
			keys[i] = string(key)
		}

		// Test temporal ordering - timestamps should be in chronological order
		for i := 1; i < len(keys); i++ {
			prevParts := strings.Split(keys[i-1], "\x00")
			currParts := strings.Split(keys[i], "\x00")

			if len(prevParts) >= 4 && len(currParts) >= 4 {
				prevTime := prevParts[3]
				currTime := currParts[3]

				if prevTime > currTime {
					t.Errorf("Keys not in chronological order at index %d:\n  Previous time: %s\n  Current time:  %s",
						i, prevTime, currTime)
				}
			}
		}

		// Test range query scenarios
		testRanges := []struct {
			name           string
			startHours     int
			endHours       int
			expectedEvents int
		}{
			{"First Day", 0, 23, 3},    // Hours 0,1,2 (lodash, express, react)
			{"First Week", 0, 167, 7},  // + Hours 24,25,72,96 (vuln + update + axios + moment)
			{"First Month", 0, 719, 7}, // Same as first week (no new events until hour 720)
			{"Full Timeline", 0, 1500, len(events)},
		}

		for _, tr := range testRanges {
			t.Run(tr.name, func(t *testing.T) {
				startTime := baseTime.Add(time.Duration(tr.startHours) * time.Hour)
				endTime := baseTime.Add(time.Duration(tr.endHours) * time.Hour)

				count := 0
				for _, key := range keys {
					parts := strings.Split(key, "\x00")
					if len(parts) >= 4 {
						timestampStr := parts[3]
						if timestamp, err := time.Parse(timeEncoding, timestampStr); err == nil {
							if (timestamp.Equal(startTime) || timestamp.After(startTime)) &&
								(timestamp.Before(endTime) || timestamp.Equal(endTime)) {
								count++
							}
						}
					}
				}

				if count != tr.expectedEvents {
					t.Errorf("Range %s: expected %d events, got %d", tr.name, tr.expectedEvents, count)
				}
			})
		}
	})

	t.Run("LargeScaleQueryOptimization", func(t *testing.T) {
		// Test key structure performance with large datasets
		startTime := time.Now()

		// Generate 50,000 artifacts across different dimensions (reduced for faster testing)
		const numArtifacts = 50000
		namespaces := []string{"security", "quality", "compliance", "sca", "dast", "secrets"}
		types := []string{"vulnerability", "finding", "metric", "violation", "dependency", "license"}
		entities := make([]string, 50)

		// Generate diverse entity set
		for i := range 50 {
			entities[i] = fmt.Sprintf("repo:github.com/org/service-%03d", i)
		}

		keys := make([]string, numArtifacts)

		for i := range numArtifacts {
			// Distribute artifacts across time, namespaces, types, and entities
			artifactTime := baseTime.Add(time.Duration(i%5000) * time.Minute) // 5k different timestamps
			namespace := namespaces[i%len(namespaces)]
			artifactType := types[i%len(types)]
			entity := entities[i%len(entities)]
			artifactID := fmt.Sprintf("artifact-%06d", i)

			key := makeArtifactKey(
				namespace,
				artifactType,
				entity,
				artifactTime.Format(timeEncoding),
				artifactID,
			)
			keys[i] = string(key)
		}

		generationTime := time.Since(startTime)
		t.Logf("Generated %d keys in %v (%.2f keys/ms)",
			numArtifacts, generationTime, float64(numArtifacts)/float64(generationTime.Milliseconds()))

		// Test prefix query performance
		startTime = time.Now()
		securityPrefix := "security\x00"
		securityCount := 0
		for _, key := range keys {
			if strings.HasPrefix(key, securityPrefix) {
				securityCount++
			}
		}
		prefixQueryTime := time.Since(startTime)

		expectedSecurityCount := numArtifacts / len(namespaces) // ~1/6 of all artifacts
		tolerance := expectedSecurityCount / 10                 // 10% tolerance

		if securityCount < expectedSecurityCount-tolerance || securityCount > expectedSecurityCount+tolerance {
			t.Errorf("Security prefix query returned %d results, expected ~%d", securityCount, expectedSecurityCount)
		}

		t.Logf("Prefix query over %d keys took %v (%d results)",
			numArtifacts, prefixQueryTime, securityCount)

		// Performance regression test - these should complete quickly
		if generationTime > 200*time.Millisecond {
			t.Errorf("Key generation too slow: %v > 200ms", generationTime)
		}
		if prefixQueryTime > 20*time.Millisecond {
			t.Errorf("Prefix query too slow: %v > 20ms", prefixQueryTime)
		}
	})
}

func TestDeepAnalyticalScenarios(t *testing.T) {
	// Test complex analytical scenarios that require efficient key structure

	t.Run("GitCommitToDependencyTracing", func(t *testing.T) {
		// Test ability to trace from dependency changes back to commits and PRs
		repoEntity := "repo:github.com/org/production-app"

		// Simulate a complete dependency change workflow
		scenarios := []struct {
			timestamp  time.Time
			commitHash string
			prNumber   string
			author     string
			dependency string
			oldVersion string
			newVersion string
			reason     string
		}{
			{
				timestamp:  time.Date(2025, 1, 15, 10, 30, 0, 0, time.UTC),
				commitHash: "a1b2c3d4",
				prNumber:   "PR-1234",
				author:     "dev@company.com",
				dependency: "lodash",
				oldVersion: "4.17.20",
				newVersion: "4.17.21",
				reason:     "security-patch",
			},
			{
				timestamp:  time.Date(2025, 2, 3, 14, 15, 0, 0, time.UTC),
				commitHash: "e5f6g7h8",
				prNumber:   "PR-1567",
				author:     "security@company.com",
				dependency: "moment",
				oldVersion: "2.29.4",
				newVersion: "",
				reason:     "remove-deprecated-package",
			},
			{
				timestamp:  time.Date(2025, 2, 3, 14, 20, 0, 0, time.UTC),
				commitHash: "e5f6g7h8",
				prNumber:   "PR-1567",
				author:     "security@company.com",
				dependency: "date-fns",
				oldVersion: "",
				newVersion: "2.30.0",
				reason:     "replace-moment-with-secure-alternative",
			},
		}

		// Generate artifacts for each scenario
		var dependencyKeys []string

		for i, scenario := range scenarios {
			// Dependency change artifact
			depChangeID := fmt.Sprintf("dep-change-%d", i)
			depKey := makeArtifactKey(
				"sca",
				"dependency-change",
				repoEntity,
				scenario.timestamp.Format(timeEncoding),
				depChangeID,
			)
			dependencyKeys = append(dependencyKeys, string(depKey))
		}

		// Test correlation queries - find all changes for a specific timeframe
		startDate := time.Date(2025, 2, 1, 0, 0, 0, 0, time.UTC)
		endDate := time.Date(2025, 2, 28, 23, 59, 59, 0, time.UTC)

		lowerBound := startDate.Format(timeEncoding)
		upperBound := endDate.Format(timeEncoding) + "~"

		// Find dependency changes in February
		februaryDepChanges := 0
		for _, key := range dependencyKeys {
			parts := strings.Split(key, "\x00")
			if len(parts) >= 4 {
				timestamp := parts[3]
				if timestamp >= lowerBound && timestamp < upperBound {
					februaryDepChanges++
				}
			}
		}

		if februaryDepChanges != 2 { // moment removal + date-fns addition
			t.Errorf("Expected 2 dependency changes in February, got %d", februaryDepChanges)
		}

		// Test multi-dimensional analysis - group by commit
		commitToChanges := make(map[string][]string)
		for i, scenario := range scenarios {
			commitToChanges[scenario.commitHash] = append(
				commitToChanges[scenario.commitHash],
				dependencyKeys[i],
			)
		}

		// Verify commit e5f6g7h8 has 2 dependency changes (remove moment + add date-fns)
		if len(commitToChanges["e5f6g7h8"]) != 2 {
			t.Errorf("Expected commit e5f6g7h8 to have 2 dependency changes, got %d",
				len(commitToChanges["e5f6g7h8"]))
		}
	})

	t.Run("SecurityPostureTrendAnalysis", func(t *testing.T) {
		// Test analyzing security posture trends across multiple dimensions
		baseTime := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)

		// Generate 6 months of security data across multiple repos
		repos := []string{
			"repo:github.com/org/legacy-app",
			"repo:github.com/org/new-microservice",
			"repo:github.com/org/mobile-app",
		}

		var allKeys []string

		// Simulate improving security posture over time for new-microservice
		// Degrading posture for legacy-app
		// Stable posture for mobile-app

		for month := 0; month < 6; month++ {
			for day := 0; day < 30; day++ {
				currentTime := baseTime.Add(time.Duration(month*30+day) * 24 * time.Hour)

				for repoIdx, repo := range repos {
					var dailyFindings []struct {
						severity string
						type_    string
						count    int
					}

					switch repoIdx {
					case 0: // legacy-app - degrading security
						baseFindings := 5 + month*2 // increasing findings over time
						dailyFindings = []struct {
							severity string
							type_    string
							count    int
						}{
							{"CRITICAL", "vulnerability", baseFindings / 5},
							{"HIGH", "sast-finding", baseFindings / 3},
							{"MEDIUM", "secret-leak", baseFindings / 4},
							{"LOW", "license-violation", baseFindings / 2},
						}

					case 1: // new-microservice - improving security
						baseFindings := 10 - month // decreasing findings over time
						if baseFindings < 2 {
							baseFindings = 2
						}
						dailyFindings = []struct {
							severity string
							type_    string
							count    int
						}{
							{"CRITICAL", "vulnerability", max(0, baseFindings/8)},
							{"HIGH", "sast-finding", baseFindings / 4},
							{"MEDIUM", "secret-leak", baseFindings / 6},
							{"LOW", "license-violation", baseFindings / 3},
						}

					case 2: // mobile-app - stable
						dailyFindings = []struct {
							severity string
							type_    string
							count    int
						}{
							{"CRITICAL", "vulnerability", 1},
							{"HIGH", "sast-finding", 2},
							{"MEDIUM", "secret-leak", 1},
							{"LOW", "license-violation", 3},
						}
					}

					// Generate findings for this day
					for _, finding := range dailyFindings {
						for i := 0; i < finding.count; i++ {
							findingTime := currentTime.Add(time.Duration(i) * time.Hour)
							findingID := fmt.Sprintf("%s-%s-%d-%d-%d",
								finding.type_, finding.severity, month, day, i)

							key := makeArtifactKey(
								"security",
								finding.type_,
								repo,
								findingTime.Format(timeEncoding),
								findingID,
							)
							allKeys = append(allKeys, string(key))
						}
					}
				}
			}
		}

		// Test trend analysis by extracting metrics by month and repo
		monthlyMetrics := make(map[string]map[int]int) // repo -> month -> count

		for _, key := range allKeys {
			parts := strings.Split(key, "\x00")
			if len(parts) >= 4 {
				repo := parts[2]
				timestampStr := parts[3]

				if timestamp, err := time.Parse(timeEncoding, timestampStr); err == nil {
					month := int(timestamp.Sub(baseTime).Hours() / (24 * 30))
					if monthlyMetrics[repo] == nil {
						monthlyMetrics[repo] = make(map[int]int)
					}
					monthlyMetrics[repo][month]++
				}
			}
		}

		// Verify trends
		legacyApp := "repo:github.com/org/legacy-app"
		microservice := "repo:github.com/org/new-microservice"
		mobileApp := "repo:github.com/org/mobile-app"

		// Legacy app should show increasing trend
		if monthlyMetrics[legacyApp][0] >= monthlyMetrics[legacyApp][5] {
			t.Errorf("Legacy app should show degrading security (increasing findings): month 0 = %d, month 5 = %d",
				monthlyMetrics[legacyApp][0], monthlyMetrics[legacyApp][5])
		}

		// Microservice should show improving trend
		if monthlyMetrics[microservice][0] <= monthlyMetrics[microservice][5] {
			t.Errorf("Microservice should show improving security (decreasing findings): month 0 = %d, month 5 = %d",
				monthlyMetrics[microservice][0], monthlyMetrics[microservice][5])
		}

		// Mobile app should be relatively stable
		variance := abs(monthlyMetrics[mobileApp][0] - monthlyMetrics[mobileApp][5])
		if variance > monthlyMetrics[mobileApp][0]/2 { // variance should be < 50%
			t.Errorf("Mobile app should have stable security posture, but variance is too high: %d", variance)
		}

		t.Logf("Security trend analysis completed for %d total findings across 3 repos over 6 months", len(allKeys))
	})
}

// Helper functions
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}
