package main

import (
	"encoding/csv"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "Usage: %s <audit-report-pdf-file> <scope>\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  scope: CA, BRSSL, EVSSL, CS, SMIME, NETSEC, MC\n")
		os.Exit(1)
	}

	pdfPath := os.Args[1]
	scope := strings.ToUpper(os.Args[2])

	// Use pdftotext to extract text (- means stdout)
	cmd := exec.Command("pdftotext", "-layout", pdfPath, "-")
	out, err := cmd.Output()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error running pdftotext: %v\n", err)
		os.Exit(1)
	}

	// Save full pdftotext output to a .txt file in the current directory
	baseName := strings.TrimSuffix(filepath.Base(pdfPath), filepath.Ext(pdfPath))
	txtPath := baseName + ".txt"
	if err := os.WriteFile(txtPath, out, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing %s: %v\n", txtPath, err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "Saved pdftotext output to %s\n", txtPath)

	text := string(out)

	// Find start marker: "Attachment B – In-Scope CAs" or "Attachment C –"
	reStart := regexp.MustCompile(`(?i)(?:^|\n)(.*Attachment\s+([BC])\s*[–—-]\s*In[- ]Scope\s+CAs)`)
	startMatch := reStart.FindStringSubmatchIndex(text)
	if startMatch == nil {
		// Fall back to shorter "Attachment C –" match
		reStart = regexp.MustCompile(`(?i)(?:^|\n)(.*Attachment\s+([C])\s*[–—-])`)
		startMatch = reStart.FindStringSubmatchIndex(text)
	}

	var startIdx int
	var endLetterStart string
	if startMatch != nil {
		// Determine which letter was matched to set the end boundary
		matchedLetter := strings.ToUpper(text[startMatch[4]:startMatch[5]])
		endLetterStart = string(rune(matchedLetter[0] + 1)) // next letter after matched

		// Trim any leading newline from the match
		startIdx = startMatch[0]
		if text[startIdx] == '\n' {
			startIdx++
		}
	} else {
		// No attachment marker found; treat beginning of text as start
		fmt.Fprintln(os.Stderr, "Warning: no 'Attachment B/C' marker found; using beginning of text")
		startIdx = 0
		endLetterStart = "B"
	}

	// Find the start of the next attachment after the matched one
	remainder := text[startIdx:]
	reEnd := regexp.MustCompile(`(?im)^.*(Attachment\s+[` + endLetterStart + `-Z]\b|Docusign\s+Envelope\s+ID)`)
	endLoc := reEnd.FindStringIndex(remainder)

	var appendixC string
	if endLoc != nil {
		appendixC = remainder[:endLoc[0]]
	} else {
		appendixC = remainder
	}

	// Filter the extracted text
	lines := strings.Split(appendixC, "\n")
	var filtered []string
	reHeader := regexp.MustCompile(`(?i)Attachment\s+[BC]\s*[–—-](\s*In[- ]Scope\s+CAs)?`)
	reSection := regexp.MustCompile(`(?i)^\s*(Root CA Certificates|Subordinate CA Certificates)\s*$`)
	rePageNum := regexp.MustCompile(`^\s*\d+\s*$`)
	reSubjectDN := regexp.MustCompile(`(?i)^\s*Subject\s+DN\b`)
	reExpectedHeadings := regexp.MustCompile(`(?i)^\s*Subject\s+DN\s+SHA-?256\s+Thumbprint\s+Valid\s+From\s+Valid\s+To\s*$`)
	for _, line := range lines {
		// Strip the header line
		if reHeader.MatchString(line) {
			continue
		}
		// Validate and strip "Subject DN" column header lines
		if reSubjectDN.MatchString(line) {
			if !reExpectedHeadings.MatchString(line) {
				fmt.Fprintf(os.Stderr, "Error: unexpected column headings: %s\n", strings.TrimSpace(line))
				os.Exit(1)
			}
			continue
		}
		// Strip section headers, preceding page number, and blank lines before that
		if reSection.MatchString(line) {
			// Remove page number line if present
			if len(filtered) > 0 && rePageNum.MatchString(filtered[len(filtered)-1]) {
				filtered = filtered[:len(filtered)-1]
			}
			// Remove trailing blank lines
			for len(filtered) > 0 && strings.TrimSpace(filtered[len(filtered)-1]) == "" {
				filtered = filtered[:len(filtered)-1]
			}
			continue
		}
		filtered = append(filtered, line)
	}

	// Strip trailing blank lines, then page number, then blank lines again
	for len(filtered) > 0 && strings.TrimSpace(filtered[len(filtered)-1]) == "" {
		filtered = filtered[:len(filtered)-1]
	}
	for len(filtered) > 0 && rePageNum.MatchString(filtered[len(filtered)-1]) {
		filtered = filtered[:len(filtered)-1]
	}
	for len(filtered) > 0 && strings.TrimSpace(filtered[len(filtered)-1]) == "" {
		filtered = filtered[:len(filtered)-1]
	}

	// Parse filtered lines into records
	reRecord := regexp.MustCompile(`^(.*?)\s+([0-9A-Fa-f]{64})\s+(\d{1,2}/\d{1,2}/\d{4})\s+(\d{1,2}/\d{1,2}/\d{4})\s*$`)
	reRecordLoose := regexp.MustCompile(`^(.*?)\s+([0-9A-Fa-f]{60,68})\s+(\d{1,2}/\d{1,2}/\d{4})\s+(\d{1,2}/\d{1,2}/\d{4})\s*$`)
	// Partial record: SHA-256 wraps to the next line (pdftotext -layout column overflow)
	rePartialRecord := regexp.MustCompile(`^(.*?)\s+([0-9A-Fa-f]{20,63})\s+(\d{1,2}/\d{1,2}/\d{3,4})\s+(\d{1,2}/\d{1,2}/\d{3,4})\s*$`)
	// SHA continuation: subject text + hex chars + optional trailing date digits (one or two groups)
	reShaCont := regexp.MustCompile(`^(.*?)\s+([0-9A-Fa-f]+)(?:\s{2,}(\d{1,4}))?(?:\s{2,}(\d{1,4}))?\s*$`)

	type pendingRecord struct {
		subjectDN string
		sha256    string
		validFrom string
		validTo   string
	}

	var records []Record
	var pending *pendingRecord
	var orphanLines []string // lines before first record that might be a subject
	for _, line := range filtered {
		if strings.TrimSpace(line) == "" {
			continue
		}

		// If we have a pending partial record, try to get SHA continuation
		if pending != nil {
			mc := reShaCont.FindStringSubmatch(line)
			if mc != nil && len(pending.sha256) < 64 {
				pending.subjectDN += "\n" + strings.TrimSpace(mc[1])
				pending.sha256 += mc[2]
				// Assign trailing digit groups to dates with incomplete years
				trailing := []string{}
				if mc[3] != "" {
					trailing = append(trailing, mc[3])
				}
				if mc[4] != "" {
					trailing = append(trailing, mc[4])
				}
				i := 0
				if i < len(trailing) && dateNeedsCompletion(pending.validFrom) {
					pending.validFrom += trailing[i]
					i++
				}
				if i < len(trailing) && dateNeedsCompletion(pending.validTo) {
					pending.validTo += trailing[i]
					i++
				}
				if len(pending.sha256) >= 64 {
					records = append(records, Record{
						SubjectDN: pending.subjectDN,
						SHA256:    pending.sha256,
						ValidFrom: pending.validFrom,
						ValidTo:   pending.validTo,
					})
					pending = nil
				}
				continue
			}
			// Continuation didn't match or SHA already complete; finalize pending record
			if len(pending.sha256) != 64 {
				fmt.Fprintf(os.Stderr, "Warning: incomplete SHA-256 (%d chars) for: %s\n", len(pending.sha256), firstLine(pending.subjectDN))
			}
			records = append(records, Record{
				SubjectDN: pending.subjectDN,
				SHA256:    pending.sha256,
				ValidFrom: pending.validFrom,
				ValidTo:   pending.validTo,
			})
			pending = nil
			// Fall through to process this line normally
		}

		m := reRecord.FindStringSubmatch(line)
		if m == nil {
			m = reRecordLoose.FindStringSubmatch(line)
			if m != nil {
				fmt.Fprintf(os.Stderr, "Warning: record has %d-char SHA256 (expected 64): %s\n", len(m[2]), m[2])
			}
		}
		if m != nil {
			// New record
			subj := strings.TrimSpace(m[1])
			if subj == "" {
				// SHA+dates on their own line; recover subject
				subj = recoverSubject(records, orphanLines)
			}
			records = append(records, Record{
				SubjectDN: subj,
				SHA256:    m[2],
				ValidFrom: m[3],
				ValidTo:   m[4],
			})
			orphanLines = nil
		} else {
			// Try partial record match (SHA-256 wrapped to next line)
			mp := rePartialRecord.FindStringSubmatch(line)
			if mp != nil {
				subj := strings.TrimSpace(mp[1])
				if subj == "" {
					subj = recoverSubject(records, orphanLines)
				}
				pending = &pendingRecord{
					subjectDN: subj,
					sha256:    mp[2],
					validFrom: mp[3],
					validTo:   mp[4],
				}
				orphanLines = nil
			} else if len(records) > 0 {
				// Continuation of Subject DN
				records[len(records)-1].SubjectDN += "\n" + strings.TrimSpace(line)
			} else {
				orphanLines = append(orphanLines, strings.TrimSpace(line))
			}
		}
	}
	// Finalize any trailing pending record
	if pending != nil {
		if len(pending.sha256) != 64 {
			fmt.Fprintf(os.Stderr, "Warning: incomplete SHA-256 (%d chars) for: %s\n", len(pending.sha256), firstLine(pending.subjectDN))
		}
		records = append(records, Record{
			SubjectDN: pending.subjectDN,
			SHA256:    pending.sha256,
			ValidFrom: pending.validFrom,
			ValidTo:   pending.validTo,
		})
	}

	// Build lookup of PDF records by SHA-256
	pdfBySHA := make(map[string]Record)
	for _, r := range records {
		pdfBySHA[strings.ToUpper(r.SHA256)] = r
	}

	// Download and parse the GitHub CSV
	csvRecords, err := downloadCSV()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error downloading CSV: %v\n", err)
		os.Exit(1)
	}

	// Determine which column corresponds to the scope
	scopeCol := "WT" + scope + "?"
	headers := csvRecords[0]
	scopeIdx := -1
	for i, h := range headers {
		if strings.EqualFold(strings.TrimSpace(h), scopeCol) {
			scopeIdx = i
			break
		}
	}
	if scopeIdx < 0 {
		fmt.Fprintf(os.Stderr, "Error: scope column %q not found in CSV headers: %v\n", scopeCol, headers)
		os.Exit(1)
	}

	// Find column indices for comparison fields
	colIdx := make(map[string]int)
	for _, name := range []string{"Subject DN", "SHA-256(Certificate)", "Not Before", "Not After", "CA Owner", "CCADB Revocation Status"} {
		for i, h := range headers {
			if strings.EqualFold(strings.TrimSpace(h), name) {
				colIdx[name] = i
				break
			}
		}
	}

	// Filter CSV to in-scope rows and compare
	var anomalies []string
	csvInScope := make(map[string]bool)
	csvRevoked := make(map[string]bool)
	for _, row := range csvRecords[1:] {
		if scopeIdx >= len(row) {
			continue
		}
		val := strings.TrimSpace(row[scopeIdx])
		if strings.EqualFold(val, "n/a") || val == "" {
			continue
		}
		// Skip non-Sectigo CA owners
		if ownerIdx, ok := colIdx["CA Owner"]; ok && ownerIdx < len(row) {
			owner := strings.TrimSpace(row[ownerIdx])
			if !strings.EqualFold(owner, "Sectigo") {
				continue
			}
		}
		// Skip revoked certificates
		if revIdx, ok := colIdx["CCADB Revocation Status"]; ok && revIdx < len(row) {
			status := strings.TrimSpace(row[revIdx])
			if strings.EqualFold(status, "Revoked") || strings.EqualFold(status, "Parent Cert Revoked") {
				sha := strings.ToUpper(strings.TrimSpace(row[colIdx["SHA-256(Certificate)"]]))
				csvRevoked[sha] = true
				continue
			}
		}
		// This row is in-scope
		sha := strings.ToUpper(strings.TrimSpace(row[colIdx["SHA-256(Certificate)"]]))
		csvInScope[sha] = true
		csvDN := strings.TrimSpace(row[colIdx["Subject DN"]])
		csvNotBefore := strings.TrimSpace(row[colIdx["Not Before"]])
		csvNotAfter := strings.TrimSpace(row[colIdx["Not After"]])

		pdfRec, found := pdfBySHA[sha]
		if !found {
			anomalies = append(anomalies, fmt.Sprintf("IN CSV BUT NOT IN PDF: SHA256=%s DN=%s", sha, firstLine(csvDN)))
			continue
		}

		// Compare Subject DN
		pdfDNNorm := normalizeDN(pdfRec.SubjectDN)
		csvDNNorm := normalizeDN(csvDN)
		if pdfDNNorm != csvDNNorm {
			// Check if difference is only whitespace introduced by pdftotext line wrapping
			if stripSpaces(pdfDNNorm) != stripSpaces(csvDNNorm) {
				anomalies = append(anomalies, fmt.Sprintf("SUBJECT DN MISMATCH: SHA256=%s\n  PDF: %s\n  CSV: %s",
					sha, oneLine(pdfRec.SubjectDN), oneLine(csvDN)))
			}
		}

		// Compare dates (PDF: M/D/YYYY, CSV: YYYY-MM-DD HH:MM:SS)
		if !datesMatch(pdfRec.ValidFrom, csvNotBefore) {
			anomalies = append(anomalies, fmt.Sprintf("VALID FROM MISMATCH: SHA256=%s PDF=%s CSV=%s",
				sha, pdfRec.ValidFrom, csvNotBefore))
		}
		if !datesMatch(pdfRec.ValidTo, csvNotAfter) {
			anomalies = append(anomalies, fmt.Sprintf("VALID TO MISMATCH: SHA256=%s PDF=%s CSV=%s",
				sha, pdfRec.ValidTo, csvNotAfter))
		}
	}

	// Check for PDF records not in the CSV in-scope set
	for sha, r := range pdfBySHA {
		if !csvInScope[sha] && !csvRevoked[sha] {
			anomalies = append(anomalies, fmt.Sprintf("IN PDF BUT NOT IN-SCOPE IN CSV: SHA256=%s DN=%s",
				sha, firstLine(r.SubjectDN)))
		}
	}

	// Report
	fmt.Fprintf(os.Stderr, "PDF records: %d, CSV in-scope (%s): %d\n", len(records), scope, len(csvInScope))
	if len(anomalies) == 0 {
		fmt.Println("No anomalies found.")
	} else {
		fmt.Fprintf(os.Stderr, "%d anomaly(ies) found:\n", len(anomalies))
		for _, a := range anomalies {
			fmt.Println(a)
		}
	}
}

type Record struct {
	SubjectDN string
	SHA256    string
	ValidFrom string
	ValidTo   string
}

const csvURL = "https://raw.githubusercontent.com/sectigo/ca_certificate_lists/main/audit/list_for_audit.csv"

func downloadCSV() ([][]string, error) {
	resp, err := http.Get(csvURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	// Save locally
	if err := os.WriteFile("list_for_audit.csv", data, 0644); err != nil {
		return nil, err
	}
	fmt.Fprintln(os.Stderr, "Downloaded list_for_audit.csv")
	r := csv.NewReader(strings.NewReader(string(data)))
	r.LazyQuotes = true
	return r.ReadAll()
}

// normalizeDN strips whitespace differences for comparison.
// Continuation lines without "=" are joined with a space (wrapped attribute values).
// CJK character boundaries are joined without a space.
// All runs of whitespace are collapsed to a single space.
func normalizeDN(dn string) string {
	lines := strings.Split(dn, "\n")
	var parts []string
	for _, l := range lines {
		t := strings.TrimSpace(l)
		if t == "" {
			continue
		}
		if len(parts) > 0 && !strings.Contains(t, "=") {
			// Join with no space if the boundary is between CJK characters
			prev := []rune(parts[len(parts)-1])
			cont := []rune(t)
			if len(prev) > 0 && len(cont) > 0 && isCJK(prev[len(prev)-1]) && isCJK(cont[0]) {
				parts[len(parts)-1] += t
			} else {
				parts[len(parts)-1] += " " + t
			}
		} else {
			parts = append(parts, t)
		}
	}
	// Collapse all whitespace runs to single space within each part
	reWS := regexp.MustCompile(`\s+`)
	for i, p := range parts {
		parts[i] = strings.TrimSpace(reWS.ReplaceAllString(p, " "))
	}
	return strings.Join(parts, "\n")
}

func isCJK(r rune) bool {
	return (r >= 0x4E00 && r <= 0x9FFF) || // CJK Unified Ideographs
		(r >= 0x3400 && r <= 0x4DBF) || // CJK Extension A
		(r >= 0xF900 && r <= 0xFAFF) || // CJK Compatibility Ideographs
		(r >= 0x20000 && r <= 0x2A6DF) || // CJK Extension B
		(r >= 0x2A700 && r <= 0x2B73F) // CJK Extension C
}

// recoverSubject handles the case where pdftotext puts the subject on its own
// line and the SHA+dates on the next line (blank subject in the regex match).
// It either pops the trailing attribute lines from the previous record or uses
// orphan lines collected before the first record.
func recoverSubject(records []Record, orphanLines []string) string {
	if len(records) > 0 {
		prev := &records[len(records)-1]
		lines := strings.Split(prev.SubjectDN, "\n")
		// Find the last line that starts a new attribute (contains "=")
		lastAttrIdx := -1
		for i := len(lines) - 1; i > 0; i-- {
			if strings.Contains(lines[i], "=") {
				lastAttrIdx = i
				break
			}
		}
		if lastAttrIdx > 0 {
			stolen := strings.Join(lines[lastAttrIdx:], "\n")
			prev.SubjectDN = strings.Join(lines[:lastAttrIdx], "\n")
			return stolen
		}
	}
	if len(orphanLines) > 0 {
		return strings.Join(orphanLines, "\n")
	}
	return ""
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i] + "..."
	}
	return s
}

func oneLine(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "\n", " / "), "\r", "")
}

func stripSpaces(s string) string {
	return strings.ReplaceAll(s, " ", "")
}

// dateNeedsCompletion returns true if the date's year has fewer than 4 digits.
func dateNeedsCompletion(date string) bool {
	parts := strings.Split(date, "/")
	if len(parts) != 3 {
		return false
	}
	return len(parts[2]) < 4
}

// datesMatch compares a PDF date (M/D/YYYY) with a CSV date (YYYY-MM-DD HH:MM:SS)
func datesMatch(pdfDate, csvDate string) bool {
	pdfDate = strings.TrimSpace(pdfDate)
	csvDate = strings.TrimSpace(csvDate)
	// Parse PDF date
	pt, err1 := time.Parse("1/2/2006", pdfDate)
	// Parse CSV date (may have time component)
	csvDate = strings.Fields(csvDate)[0] // take date part only
	ct, err2 := time.Parse("2006-01-02", csvDate)
	if err1 != nil || err2 != nil {
		return pdfDate == csvDate // fallback to string comparison
	}
	return pt.Equal(ct)
}
